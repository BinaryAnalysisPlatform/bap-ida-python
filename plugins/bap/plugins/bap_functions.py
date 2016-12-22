"""
IDA Python Plugin to get information about functions from BAP into IDA.

Finds all the locations in the executable that BAP knows to be functions and
marks them as such in IDA.

Keybindings:
    Shift-P : Run BAP and mark code as functions in IDA
"""
import idaapi
import idc

from bap.utils.run import BapIda


class FunctionFinder(BapIda):
    def __init__(self):
        super(FunctionFinder, self).__init__()
        self.action = 'looking for function starts'
        self.syms = self.tmpfile('syms', mode='r')
        self.args += [
            '--print-symbol-format', 'addr',
            '--dump', 'symbols:{0}'.format(self.syms.name)
        ]


class BAP_Functions(idaapi.plugin_t):
    """Plugin to get functions from BAP and mark them in IDA."""

    flags = idaapi.PLUGIN_FIX
    comment = "BAP Functions Plugin"
    help = "BAP Functions Plugin"
    wanted_name = "BAP: Discover functions"
    wanted_hotkey = "Shift-P"

    def mark_functions(self):
        """Run BAP, get functions, and mark them in IDA."""
        analysis = FunctionFinder()
        analysis.on_finish(lambda x: self.add_starts(x))
        analysis.run()

    def add_starts(self, bap):
        idaapi.refresh_idaview_anyway()
        for line in bap.syms:
            line = line.strip()
            if len(line) == 0:
                continue
            addr = int(line, 16)
            end_addr = idaapi.BADADDR
            idaapi.add_func(addr, end_addr)
        idc.Refresh()

    def init(self):
        """Initialize Plugin."""
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate Plugin."""
        pass

    def run(self, arg):
        self.mark_functions()


def PLUGIN_ENTRY():
    """Install BAP_Functions upon entry."""
    return BAP_Functions()
