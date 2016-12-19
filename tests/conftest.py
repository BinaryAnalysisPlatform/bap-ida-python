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
        cmd = ' '.join(args)
        patch = None
        for p in Popen.patches:
            if 'test' in p:
                if p['test'](args) or p['test'](cmd):
                    patch = p
                    break
            else:
                if p['cmd'] == cmd:
                    patch = p
                    break
        if patch:
            super(Popen, self).__init__(
                patch['script'],
                shell=True,
                **kwargs)
        else:
            super(Popen, self).__init__(args, **kwargs)


@pytest.fixture
def popenpatch(monkeypatch):
    monkeypatch.setattr('subprocess.Popen', Popen)
    
    def patch(cmd, script):
        patch = {}
        if callable(cmd):
            patch['test'] = cmd
        else:
            patch['cmd'] = cmd
        patch['script'] = script
        Popen.patches.append(patch)
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


