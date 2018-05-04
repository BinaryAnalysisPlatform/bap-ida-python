import idaapi

from bap.utils import trace


@trace.handler('pc-changed', requires=['machine-id', 'pc'])
def tev_insn(state, ev):
    idaapi.dbg_add_tev(1, state['machine-id'], state['pc'])
