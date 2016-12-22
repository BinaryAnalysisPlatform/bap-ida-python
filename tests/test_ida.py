def test_comments(addresses, comments, choice, load):
    from bap.utils import ida
    from bap.plugins import bap_clear_comments
    from bap.plugins import bap_comments

    ida.comment.handlers = []
    ida.comment.comments.clear()

    load(bap_comments)
    clear = load(bap_clear_comments)

    assert len(ida.comment.handlers) == 1

    for addr in addresses:
        ida.comment.add(addr, 'foo', 'bar')
        assert comments[addr] == 'BAP: foo=bar'
        ida.comment.add(addr, 'foo', 'baz')
        assert comments[addr] == 'BAP: foo=bar,baz'
        ida.comment.add(addr, 'bar', '()')
        assert comments[addr] == 'BAP: bar foo=bar,baz'

    clear.run(0)
    bap_cmts = [c for c in comments.values() if 'BAP:' in c]
    expected = {
        'yes': 0,
        'no': len(addresses),
        'cancel': len(addresses),
    }
    assert len(bap_cmts) == expected[choice]
