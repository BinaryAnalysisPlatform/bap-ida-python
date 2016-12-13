"""
IDA Python Plugin to use BAP to propagate taint information.

Allows user to select any arbitrary line in Graph/Text view in IDA,
and be able to taint that line and propagate taint information.

Keybindings:
    Shift-A      : Equivalent to `--taint-reg` in BAP
    Ctrl-Shift-A : Equivalent to `--taint-ptr` in BAP

Color Scheme:
    "Nasty" Yellow : Taint source
    "Affected" Red : Lines that got tainted
    "Ignored" Gray : Lines that were not visited by propagate-taint
    "Normal" White : Lines that were visited, but didn't get tainted
"""
import idautils
import idaapi
import idc
from bap.utils.run import BapIda
from bap.utils.abstract_ida_plugins import DoNothing

patterns = [
    ('true', 'gray'),
    ('is-visited', 'white'),
    ('has-taints', 'red'),
    ('taints', 'yellow')
]


class PropagateTaint(BapIda):
    "Propagate taint information using BAP"
    def __init__(self, addr, kind):
        super(PropagateTaint,self).__init__()
        self.action = 'taint propagating from {:s}0x{:X}'.format(
            '*' if kind == 'ptr' else '',
            addr)
        self.passes = ['taint','propagate-taint','map-terms','emit-ida-script']
        self.script = self.tmpfile('py')
        scheme = self.tmpfile('scm')
        for (pat,color) in patterns:
            scheme.write('(({0}) (color {1}))\n'.format(pat,color))
        scheme.close()

        self.args += [
            '--taint-'+kind, '0x{:X}'.format(addr),
            '--passes', ','.join(self.passes),
            '--map-terms-using', scheme.name,
            '--emit-ida-script-attr', 'color',
            '--emit-ida-script-file', self.script.name
        ]



class BapTaint(idaapi.plugin_t):
    flags = 0
    comment = "BAP Taint Plugin"
    wanted_name = "BAP: Taint"


    help = ""
    """
    Plugin to use BAP to propagate taint information.

    Also supports installation of callbacks using install_callback()
    """

    _callbacks = {
        'ptr': [],
        'reg': []
    }

    @classmethod
    def _do_callbacks(cls, ptr_or_reg):
        data = {
            'ea': idc.ScreenEA(),
            'ptr_or_reg': ptr_or_reg
        }
        for callback in cls._callbacks[ptr_or_reg]:
            callback(data)

    def start(self):
        tainter = PropagateTaint(idc.ScreenEA(), self.kind)
        tainter.on_finish(lambda bap: self.finish(bap))
        tainter.run()

    def finish(self, bap):
        idaapi.IDAPython_ExecScript(bap.script.name, globals())
        idaapi.refresh_idaview_anyway()
        BapTaint._do_callbacks(self.kind)
        idc.Refresh()

    def __init__(self, kind):
        assert(kind in ('ptr', 'reg'))
        self.kind = kind
        self.wanted_name += 'pointer' if kind == 'ptr' else 'value'

    def init(self):
        """Initialize Plugin."""
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate Plugin."""
        pass

    def run(self, arg):
        """
        Run Plugin.
        """
        self.start()

    @classmethod
    def install_callback(cls, callback_fn, ptr_or_reg=None):
        """
        Install callback to be run when the user calls for taint propagation.

        Callback must take a dict and must return nothing.

        Dict is guaranteed to get the following keys:
            'ea': The value of EA at point where user propagated taint from.
            'ptr_or_reg': Either 'ptr' or 'reg' depending on user selection.
        """
        if ptr_or_reg is None:
            cls.install_callback(callback_fn, 'ptr')
            cls.install_callback(callback_fn, 'reg')
        elif ptr_or_reg == 'ptr' or ptr_or_reg == 'reg':
            cls._callbacks[ptr_or_reg].append(callback_fn)
        else:
            idc.Fatal("Invalid ptr_or_reg value passed {}".
                      format(repr(ptr_or_reg)))

class BapTaintStub(DoNothing):
    pass


def PLUGIN_ENTRY():
    return BapTaintStub()
