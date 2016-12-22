import idaapi
import idc
from bap.utils import bap_comment, ida


class CommentIterator(object):

    def __init__(self, storage):
        self.storage = storage
        self.index = idc.GetFirstIndex(idc.AR_STR, storage)

    def __iter__(self):
        return self

    def next(self):
        value = idc.GetArrayElement(idc.AR_STR, self.storage)
        if value == 0:
            raise StopIteration()
        else:
            self.index = idc.GetNextIndex(idc.AR_STR, self.storage, self.index)
            return value


class CommentStorage(object):

    def __init__(self):
        name = 'bap-comments'
        existing = idc.GetArrayId(name)
        if existing < 0:
            self.storage = idc.CreateArray(name)
        else:
            self.storage = existing

    def __iter__(self):
        return CommentIterator(self.storage)

    def __len__(self):
        n = 0
        for elt in self:
            n += 1
        return n


class BapComment(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    help = 'propagate comments to IDA Views'
    comment = ''
    wanted_name = 'BAP: Comment code'
    wanted_hotkey = ''

    def init(self):
        ida.comment.register_handler(self.update)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

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
