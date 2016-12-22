""" BAP Task Manager Form """

#pylint: disable=missing-docstring,unused-argument,no-self-use,invalid-name

from __future__ import print_function

import idaapi #pylint: disable=import-error

from bap.utils.run import BapIda

class BapSelector(idaapi.Choose2):
    #pylint: disable=invalid-name,missing-docstring,no-self-use
    def __init__(self):
        idaapi.Choose2.__init__(self, 'Choose instances to kill', [
            ['#', 2],
            ['PID', 4],
            ['Action', 40],
        ], flags=idaapi.Choose2.CH_MULTI)
        self.selection = []
        self.instances = list(BapIda.instances)

    def select(self):
        choice = self.Show(modal=True)
        if choice < 0:
            return [self.instances[i] for i in self.selection]
        else:
            return [self.instances[choice]]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        bap = self.instances[n]
        return [str(n), str(bap.proc.pid), bap.action]

    def OnGetSize(self):
        return len(self.instances)

    def OnSelectionChange(self, selected):
        self.selection = selected


class BapTaskManager(idaapi.plugin_t):
    #pylint: disable=no-init
    flags = idaapi.PLUGIN_DRAW
    wanted_hotkey = "Ctrl-Alt-Shift-F5"
    comment = "bap task manager"
    help = "Open BAP Task Manager"
    wanted_name = "BAP: Task Manager"

    def run(self, arg):
        chooser = BapSelector()
        selected = chooser.select()
        for bap in selected:
            if bap in BapIda.instances:
                print('BAP> terminating '+str(bap.proc.pid))
                bap.cancel()
            else:
                print("BAP> instance {0} has already finised".
                      format(bap.proc.pid))

    def term(self):
        pass

    def init(self):
        return idaapi.PLUGIN_KEEP


def PLUGIN_ENTRY():
    return BapTaskManager()
