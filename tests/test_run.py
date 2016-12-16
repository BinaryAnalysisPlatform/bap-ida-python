def test_check_and_configure_bap(bappath, askbap, idadir):
    from bap.utils.run import check_and_configure_bap
    from bap.utils import config
    check_and_configure_bap()
    bap = config.get('bap_executable_path')
    expected = {
        'clever': bappath,
        'stupid': None
    }
    assert bap == expected[askbap['user']]
