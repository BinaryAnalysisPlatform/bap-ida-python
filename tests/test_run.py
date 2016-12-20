from functools import partial


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


def test_run_without_args(bapida):
    from bap.utils.run import BapIda
    backend, frontend = bapida
    bap = BapIda()
    bap.run()
    frontend.run()
    assert len(backend.calls) == 1
    args = backend.calls[0]['args']
    assert args[0] == backend.path
    assert '--no-ida' in args
    assert '--read-symbols-from' in args
    assert '--symbolizer=file' in args


def test_disable_symbols(bapida):
    from bap.utils.run import BapIda
    backend, frontend = bapida
    bap = BapIda(symbols=False)
    bap.run()
    frontend.run()
    assert len(backend.calls) == 1
    args = backend.calls[0]['args']
    assert args[0] == backend.path
    assert '--no-ida' in args
    assert '--read-symbols-from' not in args
    assert '--symbolizer=file' not in args


def test_event_handlers(bapida):
    from bap.utils.run import BapIda
    backend, frontend = bapida
    bap = BapIda()
    bap.events = []

    def occured(bap, event):
        bap.events.append(event)

    events = ('instance_created', 'instance_updated', 'instance_finished')
    for event in events:
        BapIda.observers[event].append(partial(occured, event=event))

    backend.on_call.append(lambda bap, args: 'sleep 1')
    bap.on_finish(lambda bap: occured(bap, 'success'))

    bap.run()
    frontend.run()

    for msg in frontend.log:
        print(msg)

    for event in events:
        assert event in bap.events

    assert 'success' in bap.events


def test_failure(bapida):
    from bap.utils.run import BapIda
    backend, frontend = bapida
    bap = BapIda()
    bap.events = []

    backend.on_call.append(lambda bap, args: 1)
    bap.on_finish(lambda bap: bap.events.append('success'))

    bap.run()
    frontend.run()

    for msg in frontend.log:
        print(msg)

    assert 'success' not in bap.events
    assert len(BapIda.instances) == 0


def test_cancel(bapida):
    from bap.utils.run import BapIda
    backend, frontend = bapida
    bap = BapIda()
    bap.events = []

    backend.on_call.append(lambda bap, args: 'sleep 100')
    frontend.register_timer(600, lambda: bap.cancel())

    bap.on_finish(lambda bap: bap.events.append('success'))
    bap.on_cancel(lambda bap: bap.events.append('canceled'))

    bap.run()
    frontend.run()

    assert 'success' not in bap.events
    assert 'canceled' in bap.events
    assert len(BapIda.instances) == 0
