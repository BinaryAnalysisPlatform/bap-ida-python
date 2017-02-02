from bap.utils.bap_comment import parse, dumps, is_valid


def test_parse():
    assert parse('hello') is None
    assert parse('BAP: hello') == {'hello': []}
    assert parse('BAP: hello,world') == {'hello': [], 'world': []}
    assert parse('BAP: hello=cruel,world') == {'hello': ['cruel', 'world']}
    assert parse('BAP: hello="hello, world"') == {'hello': ['hello, world']}
    assert parse('BAP: hello=cruel,world goodbye=real,life') == {
        'hello':   ['cruel', 'world'],
        'goodbye': ['real', 'life']
    }
    assert parse('BAP: hello="f\'"') == {'hello': ["f'"]}


def test_dumps():
    assert 'BAP:' in dumps({'hello': []})
    assert dumps({'hello': ['cruel', 'world'], 'nice': [], 'thing': []}) == \
        'BAP: nice,thing hello=cruel,world'
    assert dumps({'hello': ["world'"]}) == 'BAP: hello="world\'"'


def test_is_valid():
    assert is_valid('BAP: hello')
    assert is_valid('BAP: hello,world')
    assert not is_valid('some comment')


def test_roundup():
    comm = {
        'x': [], 'y': [], 'z': [],
        'a': ['1', '2', '3'],
        'b': ['thing\''],
        'c': ['many things'],
        'd': ['strange \\ things'],
    }
    assert parse(dumps(parse(dumps(comm)))) == comm


def test_quotation():
    data = 'BAP: chars="{\\\"a\\\", \\\"b\\\", \\\"c\\\"}"'
    assert parse(data) == {'chars': ['{"a", "b", "c"}']}
    assert parse(data) == parse(dumps(parse(data)))


def test_single_quote():
    data = 'BAP: key="{can\\\'t do}"'
    assert parse(data) == {'key': ["{can\\'t do}"]}
