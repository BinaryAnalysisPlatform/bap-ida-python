import pytest


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


def test_comments(addresses, comments, choice):
    import sys
    sys.modules['idaapi'] = __import__('mockidaapi')
    from bap.utils.ida import add_to_comment
    from bap.plugins.bap_clear_comments import PLUGIN_ENTRY
    for key in addresses:
        add_to_comment(key, 'foo', 'bar')
        assert comments[key] == 'BAP: foo=bar'
        add_to_comment(key, 'foo', 'baz')
        assert comments[key] == 'BAP: foo=bar,baz'
        add_to_comment(key, 'bar', '()')
        assert comments[key] == 'BAP: bar foo=bar,baz'
    plugin = PLUGIN_ENTRY()
    plugin.init()
    plugin.run(0)
    bap_cmts = [c for c in comments.values() if 'BAP:' in c]
    expected = {
        'yes': 0,
        'no': len(addresses),
        'cancel': len(addresses),
    }
    assert len(bap_cmts) == expected[choice]
