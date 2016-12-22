"""
Hex-Rays Plugin to propagate taint information to Pseudocode View.

Requires BAP_Taint plugin, and installs callbacks into it.
"""

import idc
import idaapi

from bap.utils import hexrays
from bap.plugins.bap_taint import BapTaint

colors = {
    'black':   0x000000,
    'red':     0xCCCCFF,
    'green':   0x99FF99,
    'yellow':  0xC2FFFF,
    'blue':    0xFFB2B2,
    'magenta': 0xFFB2FF,
    'cyan':    0xFFFFB2,
    'white':   0xFFFFFF,
    'gray':    0xEAEAEA,
}


def next_color(current_color, ea):
    coloring_order = [
        colors[c] for c in [
            'gray',
            'white',
            'red',
            'yellow',
        ]
    ]
    BGR_MASK = 0xffffff
    ea_color = idaapi.get_item_color(ea)
    if ea_color & BGR_MASK not in coloring_order:
        return current_color
    assert(current_color & BGR_MASK in coloring_order)
    ea_idx = coloring_order.index(ea_color & BGR_MASK)
    current_idx = coloring_order.index(current_color & BGR_MASK)
    if ea_idx >= current_idx:
        return ea_color
    else:
        return current_color


class PseudocodeBapTaint(hexrays.PseudocodeVisitor):
    """Propagate taint information from Text/Graph view to Pseudocode view."""

    flags = idaapi.PLUGIN_HIDE
    comment = "BAP Taint Plugin for Pseudocode View"
    help = "BAP Taint Plugin for Pseudocode View"
    wanted_name = "BAP Taint Pseudocode"

    def visit_line(self, line):
        line.widget.bgcolor = colors['gray']
        for addr in line.extract_addresses():
            line.widget.bgcolor = next_color(line.widget.bgcolor, addr)


def PLUGIN_ENTRY():
    """Install Pseudocode_BAP_Taint upon entry."""
    return PseudocodeBapTaint()
