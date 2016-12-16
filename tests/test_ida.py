import pytest


@pytest.fixture
def addresses(monkeypatch):
    addresses = (0xDEADBEAF, 0xDEADBEEF)
    monkeypatch.setattr('bap.utils.ida.all_valid_ea', lambda: addresses)
    return addresses


@pytest.fixture
def comments(monkeypatch):
    comments = {}

    def get_cmt(ea, off):
        return comments.get(ea)

    def set_cmt(ea, val, off):
        comments[ea] = val
    monkeypatch.setattr('idaapi.get_cmt', get_cmt)
    monkeypatch.setattr('idaapi.set_cmt', set_cmt)
    return comments


@pytest.fixture(params=['yes', 'no', 'cancel'])
def choice(request, monkeypatch):
    choice = request.param
    monkeypatch.setattr('idaapi.ASKBTN_YES', 'yes')
    monkeypatch.setattr('idaapi.ASKBTN_NO', 'no')
    monkeypatch.setattr('idaapi.ASKBTN_CANCEL', 'cancel')
    monkeypatch.setattr('idaapi.askyn_c', lambda d, t: request.param)
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
