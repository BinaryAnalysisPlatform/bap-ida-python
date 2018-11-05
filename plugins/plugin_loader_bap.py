"""Loads all possible BAP IDA Python plugins."""
import os
import bap.plugins
import bap.utils.run
import idaapi


class bap_loader(idaapi.plugin_t):
    """Loads plugins from the bap/plugins directory."""

    flags = idaapi.PLUGIN_FIX
    comment = "BAP Plugin Loader"
    help = "BAP Plugin Loader"
    wanted_name = "BAP_Plugin_Loader"
    wanted_hotkey = ""

    def init(self):
        """Read directory and load as many plugins as possible."""
        self.plugins = []

        idaapi.msg("BAP Loader activated\n")

        bap.utils.run.check_and_configure_bap()

        plugin_path = os.path.dirname(bap.plugins.__file__)
        idaapi.msg("BAP> Loading plugins from {}\n".format(plugin_path))

        for plugin in sorted(os.listdir(plugin_path)):
            path = os.path.join(plugin_path, plugin)
            if not plugin.endswith('.py') or plugin.startswith('__'):
                continue  # Skip non-plugins
            idaapi.msg('BAP> Loading {}\n'.format(plugin))
            self.plugins.append(idaapi.load_plugin(path))
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Ignored."""
        pass

    def run(self, arg):
        """Ignored."""
        pass


def PLUGIN_ENTRY():
    """Load the bap_loader."""
    return bap_loader()
