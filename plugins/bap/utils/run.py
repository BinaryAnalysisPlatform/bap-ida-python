"""Utilities that interact with BAP."""

from __future__ import print_function

import tempfile
import subprocess
import os
import sys

import traceback

import idc  # pylint: disable=import-error
import idaapi  # pylint: disable=import-error
from bap.utils import ida, config


# pylint: disable=missing-docstring

class Bap(object):
    """Bap instance base class.

    Instantiate a subprocess with BAP.

    We will try to keep it clean from IDA
    specifics, so that later we can lift it to the bap-python library
    """

    DEBUG = False

    def __init__(self, bap, input_file):
        """Sandbox for the BAP process.

        Each process is sandboxed, so that all intermediated data is
        stored in a temporary directory.

        instance variables:

        - `tmpdir` -- a folder where we will put all our intermediate
          files. Might be removed on the cleanup (see cleanup for more);

        - `proc` an instance of `Popen` class if process has started,
           None otherwise

        - `args` an argument list that was passed to the `Popen`.

        - `action` a gerund describing the action, that is perfomed by
           the analysis

        - `fds` a list of opened filedescriptors to be closed on the exit

        """
        self.args = [bap, input_file]
        self.proc = None
        self.fds = []
        self.out = self.tmpfile("out")
        self.action = "running bap"

    def run(self):
        "starts BAP process"
        if self.DEBUG:
            print("BAP> {0}\n".format(' '.join(self.args)))
        self.proc = subprocess.Popen(
            self.args,
            stdout=self.out,
            stderr=subprocess.STDOUT,
            env={
                'BAP_LOG_DIR': self.tmpdir
            })

    def finished(self):
        "true is the process has finished"
        return self.proc is not None and self.proc.poll() is not None

    def close(self):
        "terminate the process if needed and cleanup"
        if not self.finished():
            if self.proc is not None:
                self.proc.terminate()
                self.proc.wait()
        self.cleanup()

    def cleanup(self):
        """Close and remove all created temporary files.

        For the purposes of debugging, files are not removed
        if BAP finished with a positive nonzero code. I.e.,
        they are removed only if BAP terminated normally, or was
        killed by a signal (terminated).

        All opened file descriptros are closed in any case."""
        for desc in self.fds:
            desc.close()

        if not self.DEBUG and (self.proc is None or
                               self.proc.returncode <= 0):
            for path in os.listdir(self.tmpdir):
                os.remove(os.path.join(self.tmpdir, path))
            os.rmdir(self.tmpdir)

    def tmpfile(self, suffix, *args, **kwargs):
        "creates a new temporary files in the self.tmpdir"
        if getattr(self, 'tmpdir', None) is None:
            # pylint: disable=attribute-defined-outside-init
            self.tmpdir = tempfile.mkdtemp(prefix="bap")

        tmp = tempfile.NamedTemporaryFile(
            delete=False,
            prefix='bap-ida',
            suffix="."+suffix,
            dir=self.tmpdir,
            *args,
            **kwargs)
        self.fds.append(tmp)
        return tmp


class BapIda(Bap):
    """BAP instance in IDA.

    Uses timer even to poll the ready status of the process.

    """
    instances = []
    poll_interval_ms = 200

    # class level handlers to observe BAP instances,
    # useful, for handling gui. See also, on_finished
    # and on_cancel, for user specific handlers.
    observers = {
        'instance_created': [],
        'instance_updated': [],
        'instance_finished': [],
    }

    def __init__(self, symbols=True):
        try:
            check_and_configure_bap()
        except:
            idc.Message('BAP> configuration failed\n{0}\n'.
                        format(str(sys.exc_info())))
            traceback.print_exc()
            raise BapIdaError()
        bap = config.get('bap_executable_path')
        if bap is None:
            idc.Warning("Can't locate BAP\n")
            raise BapNotFound()
        binary = idc.GetInputFilePath()
        super(BapIda, self).__init__(bap, binary)
        # if you run IDA inside IDA you will crash IDA
        self.args.append('--no-ida')
        self._on_finish = []
        self._on_cancel = []
        if symbols:
            self._setup_symbols()

        headers = config.is_set('ida_api.enabled')

        if headers:
            self._setup_headers(bap)

    def run(self):
        "run BAP instance"
        if len(BapIda.instances) > 0:
            answer = idaapi.askyn_c(
                idaapi.ASKBTN_YES,
                "Previous instances of BAP didn't finish yet.\
                Do you really want to start a new one?".
                format(len(BapIda.instances)))

            if answer == idaapi.ASKBTN_YES:
                self._do_run()
        else:
            self._do_run()

        idc.Message("BAP> total number of running instances: {0}\n".
                    format(len(BapIda.instances)))

    def _setup_symbols(self):
        "pass symbol information from IDA to BAP"
        with self.tmpfile("sym") as out:
            ida.dump_symbol_info(out)
            self.args += [
                "--read-symbols-from", out.name,
                "--symbolizer=file",
                "--rooter=file"
            ]

    def _setup_headers(self, bap):
        "pass type information from IDA to BAP"
        # this is very fragile, and may break in case
        # if we have several BAP instances, especially
        # when they are running on different binaries.
        # Will leave it as it is until issue #588 is
        # resolved in the upstream
        with self.tmpfile("h") as out:
            ida.dump_c_header(out)
            subprocess.call(bap, [
                '--api-add', 'c:"{0}"'.format(out.name),
            ])

        def cleanup():
            subprocess.call(bap, [
                "--api-remove", "c:{0}".
                format(os.path.basename(out.name))
            ])
        self._on_cancel.append(cleanup)
        self._on_finish.append(cleanup)

    def _do_run(self):
        try:
            super(BapIda, self).run()
            BapIda.instances.append(self)
            idaapi.register_timer(200, self.update)
            idc.SetStatus(idc.IDA_STATUS_THINKING)
            self.run_handlers(self.observers['instance_created'])
            idc.Message("BAP> created new instance with PID {0}\n".
                        format(self.proc.pid))
        except:  # pylint: disable=bare-except
            idc.Message("BAP> failed to create instance\nError: {0}\n".
                        format(str(sys.exc_info()[1])))
            traceback.print_exc()

    def run_handlers(self, handlers):
        failures = 0
        for handler in handlers:
            try:
                handler(self)
            except:  # pylint: disable=bare-except
                failures += 1
                idc.Message("BAP> {0} failed because {1}\n".
                            format(self.action, str(sys.exc_info()[1])))
                traceback.print_exc()
        if failures != 0:
            idc.Warning("Some BAP handlers failed")

    def close(self):
        super(BapIda, self).close()
        BapIda.instances.remove(self)

    def update(self):
        if self.finished():
            if self.proc.returncode == 0:
                self.run_handlers(self._on_finish)
                self.run_handlers(self.observers['instance_finished'])
                self.close()
                idc.Message("BAP> finished " + self.action + '\n')
            elif self.proc.returncode > 0:
                idc.Message("BAP> an error has occured while {0}\n".
                            format(self.action))
                with open(self.out.name) as out:
                    idc.Message('BAP> output:\n{0}\n'.format(out.read()))
            else:
                idc.Message("BAP> was killed by signal {0}\n".
                            format(-self.proc.returncode))
            return -1
        else:
            self.run_handlers(self.observers['instance_updated'])
            thinking = False
            for bap in BapIda.instances:
                if bap.finished():
                    idc.SetStatus(idc.IDA_STATUS_THINKING)
                    thinking = True
            if not thinking:
                idc.SetStatus(idc.IDA_STATUS_READY)
            return 200

    def cancel(self):
        self.run_handlers(self._on_cancel)
        self.run_handlers(self.observers['instance_finished'])
        self.close()

    def on_finish(self, callback):
        self._on_finish.append(callback)

    def on_cancel(self, callback):
        self._on_cancel.append(callback)


class BapIdaError(Exception):
    pass


class BapNotFound(BapIdaError):
    pass


BAP_FINDERS = []


def check_and_configure_bap():
    """
    Check if bap_executable_path is set in the config; ask user if necessary.

    Automagically also tries a bunch of strategies to find `bap` if it can,
    and uses this to populate the default path in the popup, to make the
    user's life easier. :)

    Also, this specifically enables the BAP API option in the config if it is
    unspecified.
    """
    if config.get('bap_executable_path') is not None:
        return

    bap_path = ''

    for find in BAP_FINDERS:
        path = find()
        if path:
            bap_path = path
            break

    # always ask a user to confirm the path that was found using heuristics
    user_path = ask_user(bap_path)
    if user_path:
        bap_path = user_path
    config.set('bap_executable_path', bap_path)


def system_path():
    try:
        return subprocess.check_output(['which', 'bap']).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def opam_path():
    try:
        cmd = ['opam', 'config', 'var', 'bap:bin']
        res = subprocess.check_output(cmd).strip()
        return os.path.join(res, 'bap')
    except OSError:
        return None


def ask_user(default_path):
    def confirm(msg):
        return idaapi.askyn_c(idaapi.ASKBTN_YES, msg) == idaapi.ASKBTN_YES

    while True:
        bap_path = idaapi.askfile_c(False, default_path, 'Path to bap')
        if bap_path is None:
            if confirm('Are you sure you don\'t want to set path?'):
                return None
            else:
                continue
        if not bap_path.endswith('bap'):
            if not confirm("Path does not end with bap. Confirm?"):
                continue
        if not os.path.isfile(bap_path):
            if not confirm("Path does not point to a file. Confirm?"):
                continue
        return bap_path


BAP_FINDERS.append(system_path)
BAP_FINDERS.append(opam_path)
