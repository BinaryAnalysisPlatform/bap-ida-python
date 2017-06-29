"""
IDA Python Plugin to get information about functions from BAP into IDA.

Finds all the locations in the executable that BAP knows to be functions and
marks them as such in IDA.

Keybindings:
    Shift-P : Run BAP and mark code as functions in IDA
"""
import idaapi
import idc

from heapq import heappush, heappop
from bap.utils.run import BapIda


class FunctionFinder(BapIda):
    def __init__(self):
        super(FunctionFinder, self).__init__(symbols=False)
        self.action = 'looking for function starts'
        self.syms = self.tmpfile('syms', mode='r')
        self.args += [
            '--print-symbol-format', 'addr',
            '--dump', 'symbols:{0}'.format(self.syms.name)
        ]

        # we can be a little bit more promiscuous since IDA will ignore
        # function starts that occur in the middle of a function
        if 'byteweight' in self.plugins and not \
           '--no-byteweight' in self.args:
            self.args += [
                '--byteweight-threshold', '0.5',
                '--byteweight-length', '4',
            ]


class BAP_Functions(idaapi.plugin_t):
    """Uses BAP to find missed functions"""

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
        syms = []
        for line in bap.syms:
            heappush(syms, int(line, 16))
        for i in range(len(syms)):
            idaapi.add_func(heappop(syms), idaapi.BADADDR)
        idc.Refresh()
        idaapi.refresh_idaview_anyway()

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
