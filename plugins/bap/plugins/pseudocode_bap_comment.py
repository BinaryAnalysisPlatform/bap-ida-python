"""Hex-Rays Plugin to propagate comments to Pseudocode View."""

from bap.utils import abstract_ida_plugins
from bap.utils import bap_comment, sexpr


class Pseudocode_BAP_Comment(abstract_ida_plugins.SimpleLine_Modifier_Hexrays):
    """Propagate comments from Text/Graph view to Pseudocode view."""

    @classmethod
    def _simpleline_modify(cls, cfunc, sl):
        sl_dict = {}

        for ea in set(cls.get_ea_list(cfunc, sl)):
            ea_comm = GetCommentEx(ea, repeatable=0)
            if ea_comm is None:
                continue
            ea_BAP_dict, _, _ = bap_comment.get_bap_comment(ea_comm)
            for e in bap_comment.get_bap_list(ea_BAP_dict):
                if isinstance(e, list) and len(e) >= 2:  # i.e. '(k v)' type
                    val_list = sl_dict.get(e[0], [])
                    if e[1:] not in val_list:
                        val_list.append(e[1:])
                    sl_dict[e[0]] = val_list

        if len(sl_dict) > 0:
            BAP_dict = ['BAP']
            for k, v in sl_dict.items():
                BAP_dict += [[k] + v]
            sl.line += '\x01\x0c // \x01\x0c'  # start comment coloring
            sl.line += sexpr.from_list(BAP_dict)
            sl.line += '\x02\x0c\x02\x0c'  # stop comment coloring

    comment = "BAP Comment on Pseudocode"
    help = "BAP Comment on Pseudocode"
    wanted_name = "BAP Comment on Pseudocode"


def PLUGIN_ENTRY():
    """Install Pseudocode_BAP_Comment upon entry."""
    return Pseudocode_BAP_Comment()
