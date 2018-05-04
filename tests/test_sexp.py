from bap.utils.sexp import parse


def test_parse():
    assert parse('()') == []
    assert parse('hello') == 'hello'
    assert parse('"hello world"') == '"hello world"'
    assert parse('(hello world)') == ['hello', 'world']
    assert parse('(() () ())') == [[], [], []]
    assert parse("hi'") == "hi'"
    assert parse('hello"') == 'hello"'
    assert parse('(hello\" cruel world\")') == ['hello"', 'cruel', 'world"']
    assert parse('(a (b c) c (d (e f) g) h') == [
        'a',
        ['b', 'c'],
        'c',
        ['d', ['e', 'f'], 'g'],
        'h'
    ]
