from idaapi import ASKBTN_YES
from bap.utils.bap_comment import get_bap_comment
from bap.utils.ida import all_valid_ea


class Main(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = "removes all BAP comments"
    help=""
    wanted_name = "BAP: Clear comments"
    wanted_hotkey = "Ctrl-Shift-S"


    def clear_bap_comments(self):
        """Ask user for confirmation and then clear (BAP ..) comments."""

        if idaapi.askyn_c(ASKBTN_YES,
                          "Delete all (BAP ..) comments?") != ASKBTN_YES:
            return

        for ea in all_valid_ea():
            old_comm = idaapi.get_cmt(ea, 0)
            if old_comm is None:
                continue
            _, start_loc, end_loc = get_bap_comment(old_comm)
            new_comm = old_comm[:start_loc] + old_comm[end_loc:]
            idaapi.set_cmt(ea, new_comm, 0)


    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.clear_bap_comments()

    def term(self): pass


def PLUGIN_ENTRY():
    return Main()
