"""Utilities that interact with IDA."""
import idaapi


def add_to_comment(ea, key, value):
    """Add key:value to comm string at EA."""
    from bap_comment import add_to_comment_string
    old_comm = idaapi.get_cmt(ea, 0)
    if old_comm is None:
        old_comm = ''
    new_comm = add_to_comment_string(old_comm, key, value)
    idaapi.set_cmt(ea, new_comm, 0)


def cfunc_from_ea(ea):
    """Get cfuncptr_t from EA."""
    func = idaapi.get_func(ea)
    if func is None:
        return None
    cfunc = idaapi.decompile(func)
    return cfunc


def all_valid_ea():
    """Return all valid EA as a Python generator."""
    from idautils import Segments
    from idc import SegStart, SegEnd
    for s in Segments():
        ea = SegStart(s)
        while ea < SegEnd(s):
            yield ea
            ea = idaapi.nextaddr(ea)


def dump_loader_info(output_filename):
    """Dump information for BAP's loader into output_filename."""
    from idautils import Segments
    import idc

    idaapi.autoWait()

    with open(output_filename, 'w+') as out:
        info = idaapi.get_inf_structure()
        size = "r32" if info.is_32bit else "r64"
        out.write("(%s %s (" % (info.get_proc_name()[1], size))
        for seg in Segments():
            out.write("\n(%s %s %d (0x%X %d))" % (
                idaapi.get_segm_name(seg),
                "code" if idaapi.segtype(seg) == idaapi.SEG_CODE else "data",
                idaapi.get_fileregion_offset(seg),
                seg, idaapi.getseg(seg).size()))
        out.write("))\n")


def dump_symbol_info(output_filename):
    """Dump information for BAP's symbolizer into output_filename."""
    from idautils import Segments, Functions
    from idc import (
        SegStart, SegEnd, GetFunctionAttr,
        FUNCATTR_START, FUNCATTR_END
    )

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

    idaapi.autoWait()

    with open(output_filename, 'w+') as out:
        for ea in Segments():
            fs = Functions(SegStart(ea), SegEnd(ea))
            for f in fs:
                out.write('("%s" 0x%x 0x%x)\n' % (
                    func_name_propagate_thunk(f),
                    GetFunctionAttr(f, FUNCATTR_START),
                    GetFunctionAttr(f, FUNCATTR_END)))


def dump_c_header(output_filename):
    """Dump type information as a C header."""
    def local_type_info():
        class my_sink(idaapi.text_sink_t):
            def __init__(self):
                try:
                    idaapi.text_sink_t.__init__(self)
                except AttributeError:
                    pass  # Older IDA versions keep the text_sink_t abstract
                self.text = []

            def _print(self, thing):
                self.text.append(thing)
                return 0

        sink = my_sink()

        idaapi.print_decls(sink, idaapi.cvar.idati, [],
                           idaapi.PDF_INCL_DEPS | idaapi.PDF_DEF_FWD)
        return sink.text

    def function_sigs():
        import idautils
        f_types = []
        for ea in idautils.Functions():
            ft = idaapi.print_type(ea, True)
            if ft is not None:
                f_types.append(ft + ';')
        return list(set(f_types))  # Set, since sometimes, IDA gives repeats

    def replacer(regex, replacement):
        import re
        r = re.compile(regex)
        return lambda s: r.sub(replacement, s)

    pp_decls = replacer(r'(struct|enum|union) ([^{} ]*);',
                        r'\1 \2; typedef \1 \2 \2;')
    pp_unsigned = replacer(r'unsigned __int(8|16|32|64)',
                           r'uint\1_t')
    pp_signed = replacer(r'(signed )?__int(8|16|32|64)',
                         r'int\2_t')
    pp_annotations = replacer(r'__(cdecl|noreturn)', r'__attribute__((\1))')
    pp_wd = lambda s: (
        replacer(r'_QWORD', r'int64_t')(
            replacer(r'_DWORD', r'int32_t')(
                replacer(r'_WORD', r'int16_t')(
                    replacer(r'_BYTE', r'int8_t')(s)))))

    def preprocess(line):
        line = pp_decls(line)
        line = pp_unsigned(line)  # Must happen before signed
        line = pp_signed(line)
        line = pp_annotations(line)
        line = pp_wd(line)
        return line

    with open(output_filename, 'w+') as out:
        for line in local_type_info() + function_sigs():
            line = preprocess(line)
            out.write(line + '\n')


def dump_brancher_info(output_filename):
    """Dump information for BAP's brancher into output_filename."""
    from idautils import CodeRefsFrom

    idaapi.autoWait()

    def dest(ea, flow):  # flow denotes whether normal flow is also taken
        return set(CodeRefsFrom(ea, flow))

    def pp(l):
        return ' '.join('0x%x' % e for e in l)

    with open(output_filename, 'w+') as out:                                        
        for ea in all_valid_ea():                                                   
            branch_dests_false = dest(ea, False)                                    
            branch_dests_true = dest(ea,True)                                       
            if len(branch_dests_false) > 0 or len(branch_dests_true) > 0:           
                out.write('(0x%x (%s) (%s))\n' % (                                  
                    ea,                                                             
                    pp(branch_dests_true - branch_dests_false),                     
                    pp(branch_dests_false)                                          
                ))


def add_hotkey(hotkey, func):
    """
    Assign hotkey to run func.

    If a pre-existing action for the hotkey exists, then this function will
    remove that action and replace it with func.

    Arguments:
        - hotkey : string (for example 'Ctrl-Shift-A')
        - func : unit function (neither accepts arguments, nor returns values)
    """
    hotkey_ctx = idaapi.add_hotkey(hotkey, func)
    if hotkey_ctx is None:
        print("Failed to register {} for {}".format(hotkey, func))
    else:
        print("Registered {} for {}".format(hotkey, func))
