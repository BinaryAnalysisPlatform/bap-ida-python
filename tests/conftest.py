import sys
import subprocess
from time import sleep

import pytest


sys.modules['idaapi'] = __import__('mockidaapi')
sys.modules['idc'] = __import__('mockidc')
sys.modules['idautils'] = __import__('mockidautils')


@pytest.fixture
def idapatch(monkeypatch):
    def patch(attrs, ns='idaapi'):
        for (k, v) in attrs.items():
            monkeypatch.setattr(ns + '.' + k, v, raising=False)
    return patch


@pytest.fixture
def addresses(monkeypatch):
    addresses = (0xDEADBEAF, 0xDEADBEEF)
    monkeypatch.setattr('bap.utils.ida.addresses', lambda: addresses)
    return addresses


@pytest.fixture
def comments(idapatch):
    cmts = {}

    def set_cmt(ea, val, off):
        cmts[ea] = val
    idapatch({
        'get_cmt': lambda ea, off: cmts.get(ea),
        'set_cmt': set_cmt
    })
    yield cmts


@pytest.fixture(scope='session')
def load():
    def load(module):
        plugin = module.PLUGIN_ENTRY()
        plugin.init()
        return plugin
    return load


@pytest.fixture(params=['yes', 'no', 'cancel'])
def choice(request, idapatch):
    choice = request.param
    idapatch({
        'ASKBTN_YES': 'yes',
        'ASKBTN_NO': 'no',
        'ASKBTN_CANCEL': 'cancel',
        'askyn_c': lambda d, t: request.param
    })
    return choice


BAP_PATH = '/opt/bin/bap'


@pytest.fixture(params=[
    ('stupid', None, 'what?', 'oh, okay', 'bap'),
    ('clever', )])
def askbap(request, idapatch, monkeypatch):
    param = list(request.param)
    user = param.pop(0)

    monkeypatch.setattr('os.path.isfile', lambda p: p == BAP_PATH)
    idapatch({'ASKBTN_YES': 'yes', 'askyn_c': lambda d, t: 'yes'})

    def ask(unk, path, msg):
        if user == 'clever':
            return path
        elif user == 'stupid':
            if len(param) > 0:
                return param.pop(0)
    idapatch({'askfile_c': ask})
    return {'user': user, 'path': BAP_PATH}


@pytest.fixture
def idadir(idapatch, tmpdir):
    idapatch({'idadir': lambda x: str(tmpdir.mkdir(x))})
    return tmpdir.dirname


class Popen(subprocess.Popen):
    patches = []

    def __init__(self, args, **kwargs):
        for patch in Popen.patches:
            script = patch(args)
            if script:
                super(Popen, self).__init__(script, shell=True, **kwargs)
                break
        else:
            super(Popen, self).__init__(args, **kwargs)


@pytest.fixture
def popenpatch(monkeypatch):
    monkeypatch.setattr('subprocess.Popen', Popen)

    def same_cmd(cmd, args):
        return cmd == ' '.join(args)

    def add(patch):
        Popen.patches.append(patch)

    def patch(*args):
        if len(args) == 1:
            add(args[0])
        elif len(args) == 2:
            add(lambda pargs: args[1] if same_cmd(args[0], pargs) else None)
        else:
            raise TypeError('popenpatch() takes 1 or two arguments ({} given)'.
                            format(len(args)))
    yield patch
    Popen.patches = []


@pytest.fixture(params=[None, BAP_PATH])
def bappath(request, popenpatch):
    path = request.param
    if path:
        popenpatch('which bap', 'echo {}'.format(path))
    else:
        popenpatch('which bap', 'false')
    popenpatch('opam config var bap:bin', 'echo undefind; false')
    return path


class Ida(object):
    '''IDA instance imitator. '''

    def __init__(self):
        self.time = 0
        self.callbacks = []
        self.log = []
        self.warnings = []
        self.status = 'ready'

    def register_timer(self, interval, cb):
        '''add a recurrent callback.

        Registers a function that will be called after the specified
        ``interval``. The function may return a positive value, that
        will effectively re-register itself. If a negative value is
        returned, then the callback will not be called anymore.

        Note: the realtime clocks are imitated with the ``sleep``
        function using 10ms increments.
        '''
        self.callbacks.append({
            'time': self.time + interval,
            'call': cb
            })

    def message(self, msg):
        self.log.append(msg)

    def warning(self, msg):
        self.warnings.append(msg)

    def set_status(self, status):
        self.status = status

    def run(self):
        '''Runs IDA event cycle.
        The function will return if there are no more callbacks.
        '''
        while self.callbacks:
            sleep(0.1)
            self.time += 100
            for cb in self.callbacks:
                if cb['time'] < self.time:
                    time = cb['call']()
                    if time is None or time < 0:
                        self.callbacks.remove(cb)
                    else:
                        cb['time'] = self.time + time


class Bap(object):
    '''BAP utility mock.

    From the perspective of the IDA integration, the bap frontend
    utility is considered a backend. So, we will refer to it as a
    backend here and later.

    This mock class mimicks the behavior of the bap backend, as the
    unit tests must not dependend on the presence of the bap
    framework.

    The instances of the backend has the following attributes:

    - ``path`` a path to bap executable
    - ``calls`` a list of calls made to backend, each call is
       a dictionary that has at least these fields:
       - args - arguments passed to the Popen call
    - ``on_call`` a list of the call event handlers. An event
       handler should be a callable, that accepts two arguments.
       The first argument is a reference to the bap backend instance,
       the second is a reference to the ``proc`` dictionary (as described
       above). If a callback returns a non None value, then this value is
       used as a return value of the call to BAP. See ``call`` method
       description for more information about the return values.
    '''

    def __init__(self, path):
        '''initializes BAP backend instance.

        Once instance corresponds to one bap installation (not to a
        process instance). See class descriptions for information about
        the instance attributes.
        '''
        self.path = path
        self.calls = []
        self.on_call = []

    def call(self, args):
        '''mocks a call to a bap executable.

        If a call returns with an integer, then it is passed to the
        shell's exit command, otherwise a string representation of a
        returned value is used to form a command, that is then passed
        to a Popen constructor.
        '''
        proc = {'args': args}
        self.calls.append(proc)
        for call in self.on_call:
            res = call(self, proc)
            if res is not None:
                return res
        return 0


@pytest.fixture
def bapida(idapatch, popenpatch, monkeypatch, idadir):
    from bap.utils import config
    ida = Ida()
    bap = Bap(BAP_PATH)

    def run_bap(args):
        if args[0] == BAP_PATH:
            res = bap.call(args) or 0
            if isinstance(res, int):
                return 'exit ' + str(res)
            else:
                return str(res)

    config.set('bap_executable_path', bap.path)
    monkeypatch.setattr('os.access', lambda p, x: p == BAP_PATH)

    idapatch({
        'register_timer': ida.register_timer,
        'get_input_ida_file_path': lambda: 'true'
    })
    idapatch(ns='idc', attrs={
        'Message': ida.message,
        'Warning': ida.warning,
        'SetStatus': ida.set_status,
    })
    popenpatch(run_bap)
    monkeypatch.setattr('bap.utils.ida.output_symbols', lambda out: None)
    return (bap, ida)
