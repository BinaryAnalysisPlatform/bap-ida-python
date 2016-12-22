from bap.plugins.bap_taint import BapTaint

class BapTaintPtr(BapTaint):
    wanted_hotkey = "Ctrl-Shift-A"
    def __init__(self):
        super(BapTaintPtr,self).__init__('ptr')


def PLUGIN_ENTRY():
    return BapTaintPtr()
