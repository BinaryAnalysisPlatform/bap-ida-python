import sys
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
