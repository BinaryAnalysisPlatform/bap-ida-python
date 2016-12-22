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
        self.tmpdir = tempfile.mkdtemp(prefix="bap")
        self.args = [bap, input_file]
        self.proc = None
        self.fds = []
        self.out = self.tmpfile("out")
        self.action = "running bap"
        self.closed = False
        self.env = {'BAP_LOG_DIR': self.tmpdir}
        if self.DEBUG:
            self.env['BAP_DEBUG'] = 'yes'

    def run(self):
        "starts BAP process"
        if self.DEBUG:
            print("BAP> {0}\n".format(' '.join(self.args)))
        self.proc = subprocess.Popen(
            self.args,
            stdout=self.out,
            stderr=subprocess.STDOUT,
            env=self.env)

    def finished(self):
        "true if the process is no longer running"
        return self.proc and self.proc.poll() is not None

    def close(self):
        "terminate the process if needed and cleanup"
        if not self.finished():
            if self.proc is not None:
                self.proc.terminate()
                self.proc.wait()
        self.cleanup()
        self.closed = True

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
        if self.tmpdir is None:
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
        'instance_canceled': [],
        'instance_failed':   [],
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
        if bap is None or not os.access(bap, os.X_OK):
            idc.Warning('''
            The bap application is either not found or is not an executable.
            Please install bap or, if it is installed, provide a path to it.
            Installation instructions are available at: http://bap.ece.cmu.edu.
            ''')
            raise BapNotFound()
        binary = idaapi.get_input_file_path()
        super(BapIda, self).__init__(bap, binary)
        # if you run IDA inside IDA you will crash IDA
        self.args.append('--no-ida')
        self._on_finish = []
        self._on_cancel = []
        self._on_failed = []
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
            ida.output_symbols(out)
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
            ida.output_types(out)
            subprocess.call(bap, [
                '--api-add', 'c:"{0}"'.format(out.name),
            ])

        def cleanup():
            subprocess.call(bap, [
                "--api-remove", "c:{0}".
                format(os.path.basename(out.name))
            ])
        self.on_cleanup(cleanup)

    def _do_run(self):
        try:
            super(BapIda, self).run()
            BapIda.instances.append(self)
            idaapi.register_timer(self.poll_interval_ms, self.update)
            idc.SetStatus(idc.IDA_STATUS_THINKING)
            self.run_handlers('instance_created')
            idc.Message("BAP> created new instance with PID {0}\n".
                        format(self.proc.pid))
        except:  # pylint: disable=bare-except
            idc.Message("BAP> failed to create instance\nError: {0}\n".
                        format(str(sys.exc_info()[1])))
            traceback.print_exc()

    def run_handlers(self, event):
        assert event in self.observers
        handlers = []
        instance_handlers = {
            'instance_canceled': self._on_cancel,
            'instance_failed':   self._on_failed,
            'instance_finished': self._on_finish,
        }

        handlers += self.observers[event]
        handlers += instance_handlers.get(event, [])

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
        if all(bap.finished() for bap in BapIda.instances):
            idc.SetStatus(idc.IDA_STATUS_READY)
        if self.finished():
            if self.proc.returncode == 0:
                self.run_handlers('instance_finished')
                self.close()
                idc.Message("BAP> finished " + self.action + '\n')
            elif self.proc.returncode > 0:
                self.run_handlers('instance_failed')
                self.close()
                idc.Message("BAP> an error has occured while {0}\n".
                            format(self.action))
            else:
                if not self.closed:
                    self.run_handlers('instance_canceled')
                idc.Message("BAP> was killed by signal {0}\n".
                            format(-self.proc.returncode))
            return -1
        else:
            self.run_handlers('instance_updated')
            return self.poll_interval_ms

    def cancel(self):
        self.run_handlers('instance_canceled')
        self.close()

    def on_cleanup(self, callback):
        self.on_finish(callback)
        self.on_cancel(callback)
        self.on_failed(callback)

    def on_finish(self, callback):
        self._on_finish.append(callback)

    def on_cancel(self, callback):
        self._on_cancel.append(callback)

    def on_failed(self, callback):
        self._on_failed.append(callback)


class BapIdaError(Exception):
    pass


class BapNotFound(BapIdaError):
    def __str__(self):
        return 'Unable to detect bap executable '


class BapFinder(object):
    def __init__(self):
        self.finders = []

    def register(self, func):
        self.finders.append(func)

    def finder(self, func):
        self.register(func)
        return func

    def find(self):
        path = None
        for find in self.finders:
            path = find()
            break
        return path


bap = BapFinder()


def check_and_configure_bap():
    """Ensures that bap location is known."""
    if not config.get('bap_executable_path'):
        path = ask_user(bap.find())
        if path and len(path) > 0:
            config.set('bap_executable_path', path)


@bap.finder
def system():
    return preadline(['which', 'bap'])


@bap.finder
def opam():
    try:
        cmd = ['opam', 'config', 'var', 'bap:bin']
        res = preadline(cmd).strip()
        if 'undefined' not in res:
            return os.path.join(res, 'bap')
        else:
            return None
    except:
        return None


def confirm(msg):
    return idaapi.askyn_c(idaapi.ASKBTN_YES, msg) == idaapi.ASKBTN_YES


def ask_user(default_path):
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


def preadline(cmd):
    try:
        res = subprocess.check_output(cmd, universal_newlines=True)
        return res.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
