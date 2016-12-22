"""Hex-Rays Plugin to propagate comments to Pseudocode View."""

import idc
import idaapi

from bap.utils import hexrays
from bap.utils import bap_comment


COLOR_START = '\x01\x0c // \x01\x0c'
COLOR_END = '\x02\x0c\x02\x0c'


def union(lhs, rhs):
    for (key, rvalues) in rhs.items():
        lvalues = lhs.setdefault(key, [])
        for value in rvalues:
            if value not in lvalues:
                lvalues.append(value)


class PseudocodeBapComment(hexrays.PseudocodeVisitor):
    """Propagate comments from Text/Graph view to Pseudocode view."""
    flags = idaapi.PLUGIN_HIDE
    comment = ""
    help = "Propagate BAP comments to pseudocode view"
    wanted_name = "BAP: <automatic-plugin>"

    def visit_line(self, line):
        comm = {}
        for address in line.extract_addresses():
            idacomm = idc.Comment(address)
            newcomm = idacomm and bap_comment.parse(idacomm) or {}
            union(comm, newcomm)
        if comm:
            line.widget.line += COLOR_START
            line.widget.line += bap_comment.dumps(comm)
            line.widget.line += COLOR_END


def PLUGIN_ENTRY():
    """Install Pseudocode_BAP_Comment upon entry."""
    return PseudocodeBapComment()
