from bap.plugins.bap_taint import BapTaint

class BapTaintReg(BapTaint):
    wanted_hotkey = "Shift-A"
    def __init__(self):
        super(BapTaintReg,self).__init__('reg')


def PLUGIN_ENTRY():
    return BapTaintReg()
