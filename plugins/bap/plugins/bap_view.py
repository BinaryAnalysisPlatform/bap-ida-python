"""BAP View Plugin to read latest BAP execution trace."""

import idaapi


class BAP_View(idaapi.plugin_t):
    """
    BAP View Plugin.

    Keybindings:
        Ctrl-Alt-Shift-S  : Open/Refresh BAP View
    """

    _view = None

    @classmethod
    def _get_store_path(cls):
        from tempfile import gettempdir
        from idaapi import get_root_filename
        return "{}/ida-bap-{}.out".format(gettempdir(), get_root_filename())

    @classmethod
    def _get_view(cls):
        """Get the BAP View, creating it if necessary."""
        if cls._view is None:
            cls._view = idaapi.simplecustviewer_t()
            created_view = cls._view.Create('BAP View')
            if not created_view:
                cls._view = None
        return cls._view

    @classmethod
    def update(cls, text):
        """Replace BAP View storage with the text."""
        with open(cls._get_store_path(), 'w') as f:
            f.write(text)

    @classmethod
    def show(cls):
        """Display BAP View to the user."""
        v = cls._get_view()
        if v is not None:
            import re
            ansi_escape = re.compile(r'\x1b[^m]*m([^\x1b]*)\x1b[^m]*m')
            recolorize = lambda s : ansi_escape.sub('\1\x22\\1\2\x22', s)
            v.ClearLines()
            with open(cls._get_store_path(), 'r') as f:
                for line in f.read().split('\n'):
                    v.AddLine(recolorize(line))
            v.Refresh()  # Ensure latest information gets to the screen
            v.Show()  # Actually show it on the screen

    flags = idaapi.PLUGIN_PROC
    wanted_hotkey = ""
    comment = "BAP View"
    help = "BAP View"
    wanted_name = "BAP View"

    def init(self):
        """Initialize BAP view to load whenever hotkey is pressed."""
        from bap.utils import ida
        ida.add_hotkey('Ctrl-Alt-Shift-S', self.show)
        self.update('\n BAP has not been run yet.')
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Close BAP View, if it exists."""
        import idc
        v = self._get_view()
        if v is not None:
            v.Close()
        idc.Exec("rm -f {}".format(self._get_store_path()))  # Cleanup

    def run(self, arg):
        """Ignore, since callbacks are installed."""
        pass


def PLUGIN_ENTRY():
    """Install BAP_View upon entry."""
    return BAP_View()
