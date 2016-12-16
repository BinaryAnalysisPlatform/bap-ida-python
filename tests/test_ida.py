def test_comments(addresses, comments, choice):
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
