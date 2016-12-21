from __future__ import print_function

from copy import copy

import idaapi
import idc


def tag_addrcode(s):
    return (s[0] == idaapi.COLOR_ON and
            s[1] == chr(idaapi.COLOR_ADDR))


class PseudocodeLineWidget(object):

    def __init__(self, parent, widget):
        self.parent = parent
        self.widget = widget

    def extract_addresses(self):
        '''A set of addresses associated with the line'''
        anchor = idaapi.ctree_anchor_t()
        line = copy(self.widget.line)
        addresses = set()

        while len(line) > 0:
            skipcode_index = idaapi.tag_skipcode(line)
            if skipcode_index == 0:  # No code found
                line = line[1:]  # Skip one character ahead
            else:
                if tag_addrcode(line):
                    addr_tag = int(line[2:skipcode_index], 16)
                    anchor.value = addr_tag
                    if anchor.is_citem_anchor() \
                       and not anchor.is_blkcmt_anchor():
                        address = self.parent.treeitems.at(addr_tag).ea
                        if address != idaapi.BADADDR:
                            addresses.add(address)
                line = line[skipcode_index:]  # Skip the colorcodes
        return addresses


class PseudocodeVisitor(idaapi.plugin_t):
    """
    Abstract Base Plugin Class to modify simplelines in Pseudocode View.

    Methods that might be useful while implementing above methods:
        - get_ea_list(self, cfunc, sl)

    Note: You will need to add a PLUGIN_ENTRY() function, to your plugin code,
    that returns an object of your plugin, which uses this Class as a super
    class.
    """

    flags = idaapi.PLUGIN_PROC
    wanted_hotkey = ""

    def visit_line(self, line):
        pass

    def visit_func(self, func):
        """Run the plugin over the given cfunc."""
        for line in func.get_pseudocode():
            self.visit_line(PseudocodeLineWidget(func, line))

    def init(self):
        """
        Ensure plugin's line modification function is called whenever needed.

        If Hex-Rays is not installed, or is not initialized yet, then plugin
        will not load. To ensure that the plugin loads after Hex-Rays, please
        name your plugin's .py file with a name that starts lexicographically
        after "hexx86f"
        """
        try:
            if idaapi.init_hexrays_plugin():
                def hexrays_event_callback(event, *args):
                    if event == idaapi.hxe_refresh_pseudocode:
                        # We use this event instead of hxe_text_ready because
                        #   MacOSX doesn't seem to work well with it
                        # TODO: Look into this
                        vu, = args
                        self.visit_func(vu.cfunc)
                    return 0
                idaapi.install_hexrays_callback(hexrays_event_callback)
            else:
                return idaapi.PLUGIN_SKIP
        except AttributeError:
            idc.Warning('''init_hexrays_plugin() not found.
            Skipping Hex-Rays plugin.''')
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        pass


def find_cfunc(ea):
    """Get cfuncptr_t from EA."""
    func = idaapi.get_func(ea)
    if func:
        return idaapi.decompile(func)
