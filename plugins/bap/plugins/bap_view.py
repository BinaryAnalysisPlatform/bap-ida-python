"""BAP View Plugin to read latest BAP execution trace."""

from __future__ import print_function
from bap.utils.run import BapIda
import re

import idaapi  # pylint: disable=import-error


class BapViews(idaapi.Choose2):
    # pylint: disable=invalid-name,missing-docstring,no-self-use
    def __init__(self, views):
        idaapi.Choose2.__init__(self, 'Choose BAP view', [
            ['PID', 4],
            ['Status', 5],
            ['Action', 40]
        ])
        self.views = views

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        view = self.views[self.views.keys()[n]]
        code = view.instance.proc.returncode
        return [
            str(view.instance.proc.pid),
            "running" if code is None else str(code),
            view.instance.action
        ]

    def OnGetSize(self):
        return len(self.views)


class View(idaapi.simplecustviewer_t):
    # pylint: disable=invalid-name,missing-docstring,no-self-use
    # pylint: disable=super-on-old-class,no-member
    def __init__(self, caption, instance, on_close=None):
        super(View, self).__init__()
        self.Create(caption)
        self.instance = instance
        self.on_close = on_close

    def update(self):
        self.ClearLines()
        with open(self.instance.out.name, 'r') as src:
            for line in src.read().split('\n'):
                self.AddLine(recolorize(line))
        self.Refresh()  # Ensure latest information gets to the screen

    def OnClose(self):
        self.ClearLines()
        if self.on_close:
            self.on_close()


class BapView(idaapi.plugin_t):
    """
    BAP View Plugin.

    Keybindings:
        Ctrl-Shift-F5  : Open/Refresh BAP View
    """
    flags = idaapi.PLUGIN_DRAW
    wanted_hotkey = "Ctrl-Shift-F5"
    comment = "bap output viewer"
    help = "View BAP output"
    wanted_name = "BAP: Show output"

    def __init__(self):
        self.views = {}

    def create_view(self, bap):
        "creates a new view"
        pid = bap.proc.pid
        name = 'BAP-{0}'.format(pid)
        view = View(name, bap, on_close=lambda: self.delete_view(pid))
        view.instance = bap
        curr = idaapi.get_current_tform()
        self.views[pid] = view
        view.Show()  # pylint: disable=no-member
        idaapi.switchto_tform(curr, True)

    def delete_view(self, pid):
        "deletes a view associated with the provided pid"
        del self.views[pid]

    def update_view(self, bap):
        """updates the view associated with the given bap instance"""
        view = self.views.get(bap.proc.pid, None)
        if view:
            view.update()

    def finished(self, bap):
        "final update"
        self.update_view(bap)
        if bap.proc.pid in self.views:  # because a user could close the view
            if bap.proc.returncode > 0:
                self.views[bap.proc.pid].Show()  # pylint: disable=no-member

    def init(self):
        """Initialize BAP view to load whenever hotkey is pressed."""
        BapIda.observers['instance_created'].append(self.create_view)
        BapIda.observers['instance_updated'].append(self.update_view)
        BapIda.observers['instance_finished'].append(self.finished)
        BapIda.observers['instance_failed'].append(self.finished)
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Close BAP View, if it exists."""
        for pid in self.views:
            self.views[pid].Close()

    def show_view(self):
        "Switch to one of the BAP views"
        chooser = BapViews(self.views)
        choice = chooser.Show(modal=True)  # pylint: disable=no-member
        if choice >= 0:
            view = self.views[self.views.keys()[choice]]
            view.Show()

    def run(self, arg):  # pylint: disable=unused-argument
        "invokes the plugin"
        self.show_view()


def recolorize(line):
    """fix ansi colors"""
    ansi_escape = re.compile(r'\x1b[^m]*m([^\x1b]*)\x1b[^m]*m')
    return ansi_escape.sub('\1\x22\\1\2\x22', line)


def PLUGIN_ENTRY():  # pylint: disable=invalid-name
    """Install BAP_View upon entry."""
    return BapView()
