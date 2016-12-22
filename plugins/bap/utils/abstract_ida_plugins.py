"""Defines a few abstract plugin classes that can be subclassed for usage."""

import idaapi


class DoNothing(idaapi.plugin_t):
    """
    Do Nothing.

    This plugin does absolutely nothing. It is created for the sole purpose of
    being able to keep multiple non-plugin Python files which may then be used
    as utilities by other plugins.

    Usage:
        class DoNothing<SomeUniqueIdentifier>(DoNothing):
            pass

        def PLUGIN_ENTRY():
            return DoNothing<SomeUniqueIdentifier>()
    """

    flags = idaapi.PLUGIN_HIDE
    comment = "Does Nothing"
    help = "Does Nothing"
    wanted_name = "Do Nothing"
    wanted_hotkey = ""

    def init(self):
        """Skip plugin."""
        return idaapi.PLUGIN_SKIP

    def term(self):
        """Do nothing."""
        pass

    def run(self, arg):
        """Do nothing."""
        pass
