"""
IDA Python Plugin to get BIR attributes from an arbitrary BAP execution.

Allows user to run any BAP plugins and get information from BIR attributes,
into comments in IDA. Use the selected line's address in the command using
"{screen_ea}".

Keybindings:
    Shift-S  : Open up a window to accept arbitrary BAP commands,
                and select arbitrary BIR attributes to output to IDA comments

Comment Format:
    Comments in the Text/Graph Views are added using a key-value storage
    with the format (BAP (k1 v1) (k2 v2) ...)
"""
import idaapi
import idc

from bap.utils.run import BapIda


class BapScripter(BapIda):

    def __init__(self, user_args, attrs):
        super(BapScripter, self).__init__()
        if attrs:
            self.action = 'extracting ' + ','.join(attrs)
        else:
            self.action = 'running bap ' + user_args
        self.script = self.tmpfile('py')
        self.args += user_args.split(' ')
        self.args += [
            '--emit-ida-script',
            '--emit-ida-script-file', self.script.name
        ]
        self.args += [
            '--emit-ida-script-attr='+attr.strip()
            for attr in attrs
        ]


# perfectly random numbers
ARGS_HISTORY = 324312
ATTR_HISTORY = 234345


class BapBirAttr(idaapi.plugin_t):
    """
    Plugin to get BIR attributes from arbitrary BAP executions.

    Also supports installation of callbacks using install_callback()
    """
    flags = idaapi.PLUGIN_DRAW
    comment = "Run BAP "
    help = "Runs BAP and extracts data from the output"
    wanted_name = "BAP: Run"
    wanted_hotkey = "Shift-S"

    _callbacks = []

    recipes = {}

    def _do_callbacks(self, ea):
        for callback in self._callbacks:
            callback({'ea': ea})

    def run(self, arg):
        """
        Ask user for BAP args to pass, BIR attributes to print; and run BAP.

        Allows users to also use {screen_ea} in the BAP args to get the
        address at the location pointed to by the cursor.
        """

        args_msg = "Arguments that will be passed to `bap'"

        args = idaapi.askstr(ARGS_HISTORY, '--passes=', args_msg)
        if args is None:
            return
        attr_msg = "A comma separated list of attributes,\n"
        attr_msg += "that should be propagated to comments"
        attr_def = self.recipes.get(args, '')
        attr = idaapi.askstr(ATTR_HISTORY, attr_def, attr_msg)

        if attr is None:
            return

        # store a choice of attributes for the given set of arguments
        # TODO: store recipes in IDA's database
        self.recipes[args] = attr
        ea = idc.ScreenEA()
        attrs = []
        if attr != '':
            attrs = attr.split(',')
        analysis = BapScripter(args, attrs)
        analysis.on_finish(lambda bap: self.load_script(bap, ea))
        analysis.run()

    def load_script(self, bap, ea):
        idc.SetStatus(idc.IDA_STATUS_WORK)
        idaapi.IDAPython_ExecScript(bap.script.name, globals())
        self._do_callbacks(ea)
        idc.Refresh()
        # do we really need to call this?
        idaapi.refresh_idaview_anyway()
        idc.SetStatus(idc.IDA_STATUS_READY)

    def init(self):
        """Initialize Plugin."""
        return idaapi.PLUGIN_KEEP

    def term(self):
        """Terminate Plugin."""
        pass

    @classmethod
    def install_callback(cls, callback_fn):
        """
        Install callback to be run when the user calls for BAP execution.

        Callback must take a dict and must return nothing.

        Dict is guaranteed to get the following keys:
            'ea': The value of EA at point where user propagated taint from.
        """
        idc.Message('a callback is installed\n')
        cls._callbacks.append(callback_fn)


def PLUGIN_ENTRY():
    """Install BAP_BIR_Attr upon entry."""
    return BapBirAttr()
