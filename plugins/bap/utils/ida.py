"""Utilities that interact with IDA."""
import idaapi
import idc
import idautils

from ._service import Service
from ._comment_handler import CommentHandlers
from ._ctyperewriter import Rewriter


service = Service()
comment = CommentHandlers()
rewriter = Rewriter()


def addresses():
    """Generate all mapped addresses."""
    for s in idautils.Segments():
        ea = idc.SegStart(s)
        while ea < idc.SegEnd(s):
            yield ea
            ea = idaapi.nextaddr(ea)


@service.provider('loader')
def output_segments(out):
    """Dump binary segmentation."""
    info = idaapi.get_inf_structure()
    size = "r32" if info.is_32bit else "r64"
    out.writelines(('(', info.get_proc_name()[1], ' ', size, ' ('))
    for seg in idautils.Segments():
        out.write("\n({} {} {:d} ({:#x} {:d}))".format(
            idaapi.get_segm_name(seg),
            "code" if idaapi.segtype(seg) == idaapi.SEG_CODE else "data",
            idaapi.get_fileregion_offset(seg),
            seg, idaapi.getseg(seg).size()))
    out.write("))\n")


@service.provider('symbols')
def output_symbols(out):
    """Dump symbols."""
    try:
        from idaapi import get_func_name2 as get_func_name
        # Since get_func_name is deprecated (at least from IDA 6.9)
    except ImportError:
        from idaapi import get_func_name
        # Older versions of IDA don't have get_func_name2
        # so we just use the older name get_func_name

    def func_name_propagate_thunk(ea):
        current_name = get_func_name(ea)
        if current_name[0].isalpha():
            return current_name
        func = idaapi.get_func(ea)
        temp_ptr = idaapi.ea_pointer()
        ea_new = idaapi.BADADDR
        if func.flags & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK:
            ea_new = idaapi.calc_thunk_func_target(func, temp_ptr.cast())
        if ea_new != idaapi.BADADDR:
            ea = ea_new
        propagated_name = get_func_name(ea) or ''  # Ensure it is not `None`
        if len(current_name) > len(propagated_name) > 0:
            return propagated_name
        else:
            return current_name
            # Fallback to non-propagated name for weird times that IDA gives
            #     a 0 length name, or finds a longer import name

    for ea in idautils.Segments():
        fs = idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea))
        for f in fs:
            out.write('("%s" 0x%x 0x%x)\n' % (
                func_name_propagate_thunk(f),
                idc.GetFunctionAttr(f, idc.FUNCATTR_START),
                idc.GetFunctionAttr(f, idc.FUNCATTR_END)))


@service.provider('types')
def output_types(out):
    """Dump type information."""
    for line in local_types() + prototypes():
        out.write(rewriter.translate(line) + '\n')


@service.provider('brancher')
def output_branches(out):
    """Dump static successors for each instruction """
    for addr in addresses():
        succs = Succs(addr)
        if succs.jmps:
            out.write('{}\n'.format(succs.dumps))


def set_color(addr, color):
    idc.SetColor(addr, idc.CIC_ITEM, color)


class Printer(idaapi.text_sink_t):
    def __init__(self):
        try:
            idaapi.text_sink_t.__init__(self)
        except AttributeError:
            pass  # Older IDA versions keep the text_sink_t abstract
        self.lines = []

    def _print(self, thing):
        self.lines.append(thing)
        return 0


def local_types():
    printer = Printer()
    idaapi.print_decls(printer, idaapi.cvar.idati, [],
                       idaapi.PDF_INCL_DEPS | idaapi.PDF_DEF_FWD)
    return printer.lines


def prototypes():
    types = set()
    for ea in idautils.Functions():
        proto = idaapi.print_type(ea, True)
        if proto:
            types.append(proto + ';')
    return list(types)


def Succs(object):
    def __init__(self, addr):
        self.addr = addr
        self.dests = set(idautils.CodeRefsFrom(addr, True))
        self.jmps = set(idautils.CodeRefsFrom(addr, False))
        falls = self.succs - self.dests
        self.fall = falls[0] if falls else None

    def dumps(self):
        return ''.join([
            '({:#x} '.format(self.addr),
            ' ({:#x}) '.format(self.fall) if self.fall else '()',
            '{})'.format(sexps(self.dests))
        ])


def sexps(addrs):
    sexp = ['(']
    for addr in addrs:
        sexp.append('{:#x}'.format(addr))
    sexp.append(')')
    return ' '.join(sexp)
