def test_set_and_get(monkeypatch, tmpdir):
    monkeypatch.setattr('idaapi.idadir', lambda x:
                        str(tmpdir.mkdir(x)))
    from bap.utils.config import get, set, is_set
    for path in ('foo', 'foo.bar'):
        assert get(path) is None
        set(path, 'hello')
        assert get(path) == 'hello'
        assert not is_set(path)
        set(path, 'true')
        assert is_set(path)
