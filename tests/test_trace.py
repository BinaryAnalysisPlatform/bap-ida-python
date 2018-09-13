from bap.utils import trace

testdata = [
    {
        'input': '(pc-changed 0x10:64u)',
        'state': {
            'event': 'pc-changed',
            'pc': 0x10,
            'machine-id': 0,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(written (RAX 1:64u#1))',
        'state': {
            'event': 'written',
            'pc': 0x10,
            'machine-id': 0,
            'regs': {
                'RAX': {'value': 1, 'type': '64u', 'id': 1}
            },
            'mems': {},
        }
    },

    {
        'input': '(written (RBX 2:64u#4))',
        'state': {
            'event': 'written',
            'pc': 0x10,
            'machine-id': 0,
            'regs': {
                'RAX': {'value': 1, 'type': '64u', 'id': 1},
                'RBX': {'value': 2, 'type': '64u', 'id': 4}
            },
            'mems': {},
        }
    },

    {
        'input': '(machine-fork (0 1))',
        'state': {
            'event': 'machine-fork',
            'pc': 0x10,
            'machine-id': 1,
            'regs': {
                'RAX': {'value': 1, 'type': '64u', 'id': 1},
                'RBX': {'value': 2, 'type': '64u', 'id': 4}
            },
            'mems': {},
        }
    },

    {
        'input': '(written (ZF 1:1u#32))',
        'state': {
            'event': 'written',
            'pc': 0x10,
            'machine-id': 1,
            'regs': {
                'RAX': {'value': 1, 'type': '64u', 'id': 1},
                'RBX': {'value': 2, 'type': '64u', 'id': 4},
                'ZF':  {'value': 1, 'type': '1u',  'id': 32}
            },
            'mems': {},
        }
    },

    {
        'input': '(machine-switch (1 0))',
        'state': {
            'event': 'machine-switch',
            'pc': 0x10,
            'machine-id': 0,
            'regs': {
                'RAX': {'value': 1, 'type': '64u', 'id': 1},
                'RBX': {'value': 2, 'type': '64u', 'id': 4},
                'ZF':  {'value': 1, 'type': '1u',  'id': 32}
            },
            'mems': {},
        }
    },

    {
        'input': '(pc-changed 0x11:64u)',
        'state': {
            'event': 'pc-changed',
            'pc': 0x11,
            'machine-id': 0,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(stored (0x400:64u#42 0xDE:8u#706))',
        'state': {
            'event': 'stored',
            'pc': 0x11,
            'machine-id': 0,
            'regs': {},
            'mems': {
                0x400: {'value': 0xDE, 'type': '8u', 'id': 706}
            },
        }
    },

    {
        'input': """
        (incident-location (2602
          (677:27ee3 677:27e85 677:27e74 677:27e6b 677:27e60
            677:27edc 677:27ed0 677:27ee3 677:27e85 677:27e74
            677:27e6b 677:27e60 677:27edc 677:27ed0 677:27ee3
            677:27e85 677:27e74 677:27e6b 677:27e60 677:27edc)))
        """,
        'state': {
            'event': 'incident-location',
            'pc': 0x11,
            'machine-id': 0,
            'regs': {},
            'mems': {
                0x400: {'value': 0xDE, 'type': '8u', 'id': 706}
            },
        }
    },

    {
        'input': '(machine-switch (0 1))',
        'state': {
            'event': 'machine-switch',
            'pc': 0x11,
            'machine-id': 1,
            'regs': {},
            'mems': {
                0x400: {'value': 0xDE, 'type': '8u', 'id': 706}
            },
        }
    },

    {
        'input': '(pc-changed 0x10:64u)',
        'state': {
            'event': 'pc-changed',
            'pc': 0x10,
            'machine-id': 1,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(written (RAX 2:64u#3))',
        'state': {
            'event': 'written',
            'pc': 0x10,
            'machine-id': 1,
            'regs': {
                'RAX': {'value': 2, 'type': '64u', 'id': 3}
            },
            'mems': {},
        }
    },

    {
        'input': '(pc-changed 0x11:64u)',
        'state': {
            'event': 'pc-changed',
            'pc': 0x11,
            'machine-id': 1,
            'regs': {},
            'mems': {},
        }
    },


    {
        'input': '(call (malloc 2:64u#12))',
        'state': {
            'event': 'call',
            'pc': 0x11,
            'machine-id': 1,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(pc-changed 0x1:64u)',
        'state': {
            'event': 'pc-changed',
            'pc': 0x1,
            'machine-id': 1,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(written (RAX 2:64u#3))',
        'state': {
            'event': 'written',
            'pc': 0x1,
            'machine-id': 1,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(pc-changed 0x12:64u)',
        'state': {
            'event': 'pc-changed',
            'pc': 0x12,
            'machine-id': 1,
            'regs': {},
            'mems': {},
        }
    },

    {
        'input': '(written (RAX 2:64u#3))',
        'state': {
            'event': 'written',
            'pc': 0x12,
            'machine-id': 1,
            'regs': {
                'RAX': {'value': 2, 'type': '64u', 'id': 3}
            },
            'mems': {},
        }
    },

    {
        'input': '(machine-fork (1 2))',
        'state': {
            'event': 'machine-fork',
            'pc': 0x12,
            'machine-id': 2,
            'regs': {
                'RAX': {'value': 2, 'type': '64u', 'id': 3}
            },
            'mems': {},
        }
    },

    {
        'input': '(stored (0x600:64u#76 0xDE:64u#))',
        'state': {
            'event': 'stored',
            'pc': 0x12,
            'machine-id': 2,
            'regs': {
                'RAX': {'value': 2, 'type': '64u', 'id': 3}
            },
            'mems': {},
        }
    }
]


def test_loader():
    loader = trace.Loader('\n'.join(s['input'] for s in testdata))
    loader.enable_handlers(['regs', 'mems'])
    loader.enable_filter('filter-machine', id=[0, 1])
    loader.enable_filter('filter-range', lo=0x10, hi=0x20)
    step = 0
    for state in loader:
        assert step >= 0 and state == testdata[step]['state']
        step += 1
