"""
IDA Python Plugin to get information about functions from BAP into IDA.

Finds all the locations in the executable that BAP knows to be functions and
marks them as such in IDA.

Keybindings:
    Shift-P : Run BAP and mark code as functions in IDA
"""
import idautils


class BAP_Functions(idaapi.plugin_t):
    """Plugin to get functions from BAP and mark them in IDA."""

    @classmethod
    def mark_functions(cls):
        """Run BAP, get functions, and mark them in IDA."""
        import tempfile
        from bap.utils.run import run_bap_with

        idc.SetStatus(IDA_STATUS_WAITING)
        idaapi.refresh_idaview_anyway()

        args = {
            'symbol_file': tempfile.mkstemp(suffix='.symout',
                                                prefix='ida-bap-')[1],
        }

        run_bap_with(
            "\
            --print-symbol-format=addr \
            --dump=symbols:\"{symbol_file}\" \
            ".format(**args), no_extras=True
        )

        with open(args['symbol_file'], 'r') as f:
            for line in f:
                line = line.strip()
                if len(line) == 0:
                    continue
                addr = int(line, 16)
                end_addr = idaapi.BADADDR  # Lets IDA decide the end
                idaapi.add_func(addr, end_addr)
        
        idc.SetStatus(IDA_STATUS_READY)

        idc.Refresh()  # Force the updated information to show up

    flags = idaapi.PLUGIN_FIX
    comment = "BAP Functions Plugin"
    help = "BAP Functions Plugin"
    wanted_name = "BAP Functions Plugin"
    wanted_hotkey = ""

    def init(self):
        """Initialize Plugin."""
        from bap.utils.ida import add_hotkey
        add_hotkey("Shift-P", self.mark_functions)
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate Plugin."""
        pass

    def run(self, arg):
        """
        Run Plugin.

        Ignored since keybindings are installed.
        """
        pass


def PLUGIN_ENTRY():
    """Install BAP_Functions upon entry."""
    return BAP_Functions()
