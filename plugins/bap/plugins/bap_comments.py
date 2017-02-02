import idaapi
import idc

from bap.utils import bap_comment, ida


class Attributes(idaapi.Choose2):
    def __init__(self, comms):
        idaapi.Choose2.__init__(self, 'Select an attribute', [
            ['name', 8],
            ['addr', 8],
            ['data', 64]
        ])
        self.comms = [
            [name, '{:#x}'.format(addr), ' '.join(data)]
            for (name, addr, data) in comms
        ]

    def OnClose(self):
        pass

    def OnGetSize(self):
        return len(self.comms)

    def OnGetLine(self, n):
        return self.comms[n]


class BapComment(idaapi.plugin_t):
    flags = 0
    help = 'propagate comments to IDA Views'
    comment = ''
    wanted_name = 'BAP: View BAP Attributes'
    wanted_hotkey = 'Shift-B'

    def __init__(self):
        self.comms = {}

    def init(self):
        ida.comment.register_handler(self.update)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        comms = {}
        for addr in ida.addresses():
            comm = idaapi.get_cmt(addr, 0)
            if comm:
                try:
                    parsed = bap_comment.parse(comm)
                    if parsed:
                        for (name, data) in parsed.items():
                            comms[(addr, name)] = data
                except:
                    idc.Message("BAP> failed to parse string {0}\n{1}".
                                format(comm, str(sys.exc_info()[1])))
        comms = [(name, addr, data)
                 for ((addr, name), data) in comms.items()]
        attrs = Attributes(comms)
        choice = attrs.Show(modal=True)
        if choice >= 0:
            idc.Jump(comms[choice][1])

    def term(self):
        pass

    def update(self, ea, key, value):
        """Add key=values to comm string at EA."""
        cmt = idaapi.get_cmt(ea, 0)
        comm = cmt and bap_comment.parse(cmt) or {}
        values = comm.setdefault(key, [])
        if value and value != '()' and value not in values:
            values.append(value)
        idaapi.set_cmt(ea, bap_comment.dumps(comm), 0)


def PLUGIN_ENTRY():
    return BapComment()
