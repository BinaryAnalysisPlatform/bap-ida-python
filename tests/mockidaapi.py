# flake8: noqa

ASKBTN_YES = 0
ASKBTN_NO = 0
ASKBTN_CANCEL = 0
PLUGIN_DRAW = 0
PLUGIN_HIDE = 0
PLUGIN_KEEP = 0
PLUGIN_FIX = 0
class plugin_t(object): pass
class text_sink_t(object): pass
class Choose2(object): pass
def idadir(sub): return NotImplemented
def get_cmt(ea, off): return NotImplemented
def set_cmt(ea, off): return NotImplemented
def askyn_c(dflt, title): return NotImplemented
def get_input_file_path() : return NotImplemented
def get_segm_name(ea): return NotImplemented
