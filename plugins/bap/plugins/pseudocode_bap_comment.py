"""Hex-Rays Plugin to propagate comments to Pseudocode View."""

import idc
import idaapi

from bap.utils import hexrays
from bap.utils import bap_comment


COLOR_START = '\x01\x0c // \x01\x0c'
COLOR_END = '\x02\x0c\x02\x0c'


class PseudocodeBapComment(hexrays.PseudocodeVisitor):
    """Propagate comments from Text/Graph view to Pseudocode view."""
    flags = idaapi.PLUGIN_HIDE
    comment = ""
    help = "Propagate BAP comments to pseudocode view"
    wanted_name = "BAP: <automatic-plugin>"

    def visit_line(self, widget):
        for address in widget.extract_addresses():
            comm = idc.Comment(address)
            if comm and bap_comment.is_valid(comm):
                widget.line += COLOR_START
                widget.line += comm
                widget.line += COLOR_END


def PLUGIN_ENTRY():
    """Install Pseudocode_BAP_Comment upon entry."""
    return PseudocodeBapComment()
