import sys
import subprocess

import pytest


sys.modules['idaapi'] = __import__('mockidaapi')
sys.modules['idc'] = __import__('mockidc')


@pytest.fixture
def idapatch(monkeypatch):
    def patch(attrs, ns='idaapi'):
        for (k, v) in attrs.items():
            monkeypatch.setattr(ns + '.' + k, v, raising=False)
    return patch


@pytest.fixture
def addresses(monkeypatch):
    addresses = (0xDEADBEAF, 0xDEADBEEF)
    monkeypatch.setattr('bap.utils.ida.all_valid_ea', lambda: addresses)
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
    return cmts


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

    def __init__(self):
        self.time = 0
        self.callbacks = []
        self.log = []
        self.status = 'ready'

    def register_timer(self, interval, cb):
        self.callbacks.append({
            'time': self.time + interval,
            'call': cb
            })

    def message(self, msg):
        self.log.append(msg)

    def set_status(self, status):
        self.status = status

    def run(self):
        while self.callbacks:
            self.time += 1
            for cb in self.callbacks:
                if cb['time'] < self.time:
                    time = cb['call']()
                    if time < 0:
                        self.callbacks.remove(cb)
                    else:
                        cb['time'] = self.time + time


class Bap(object):

    def __init__(self, path):
        self.path = path
        self.calls = []

    def call(self, args):
        self.calls.append({'args': args})
        return True


@pytest.fixture
def bapida(idapatch, popenpatch, monkeypatch, idadir):
    from bap.utils import config
    ida = Ida()
    bap = Bap(BAP_PATH)

    def run_bap(args):
        if args[0] == BAP_PATH:
            if bap.call(args):
                return 'true'
            else:
                return 'false'

    config.set('bap_executable_path', bap.path)
    idapatch({
        'register_timer': ida.register_timer,
        'get_input_ida_file_path': lambda: '/bin/true'
    })
    idapatch(ns='idc', attrs={
        'Message': ida.message,
        'SetStatus': ida.set_status,
    })
    popenpatch(run_bap)
    monkeypatch.setattr('bap.utils.ida.dump_symbol_info', lambda out: None)
    return (bap, ida)
