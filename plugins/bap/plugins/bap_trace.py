# noqa: ignore=F811

import idaapi

import os


from bap.utils import trace
from PyQt5 import QtWidgets
from PyQt5 import QtGui

from PyQt5.QtCore import (
    Qt,
    QFile,
    QIODevice,
    QCryptographicHash as QCrypto,
    QRegExp,
    QTimer,
    QAbstractItemModel,
    QModelIndex,
    QVariant,
    pyqtSignal,
    QSortFilterProxyModel)


def add_insn_to_trace_view(ea, tid=1):
    idaapi.dbg_add_tev(1, tid, ea)


@trace.handler('pc-changed', requires=['machine-id', 'pc'])
def tev_insn(state, ev):
    "stores each visited instruction to the IDA Trace Window"
    add_insn_to_trace_view(state['pc'], tid=state['machine-id'])


@trace.handler('pc-changed', requires=['pc'])
def tev_insn0(state, ev):
    """stores each visited instruction to the IDA Trace Window.

    But doesn't set the pid/tid field, and keep it equal to 0
    (This enables interoperation with the debugger)
    """
    add_insn_to_trace_view(state['pc'])


@trace.handler('call', requires=['machine-id', 'pc'])
def tev_call(state, call):
    "stores call events to the IDA Trace Window"
    caller = state['pc']
    callee = idaapi.get_name_ea(0, call[0])
    idaapi.dbg_add_call_tev(state['machine-id'], caller, callee)


incidents = []
locations = {}


@trace.handler('incident')
def incident(state, data):
    incidents.append(Incident(data[0], [int(x) for x in data[1:]]))


@trace.handler('incident-location')
def incident_location(state, data):
    id = int(data[0])
    locations[id] = [parse_point(p) for p in data[1]]


# we are using PyQt5 here, because IDAPython relies on a system
# openssl 0.9.8 which is quite outdated and not available on most
# modern installations
def md5sum(filename):
    """computes md5sum of a file with the given ``filename``

    The return value is a 32 byte hexadecimal ASCII representation of
    the md5 sum (same value as returned by the ``md5sum filename`` command)
    """
    stream = QFile(filename)
    if not stream.open(QIODevice.ReadOnly | QIODevice.Text):
        raise IOError("Can't open file: " + filename)
    hasher = QCrypto(QCrypto.Md5)
    if not hasher.addData(stream):
        raise ValueError('Unable to hash file: ' + filename)
    stream.close()
    return str(hasher.result().toHex())


class HandlerSelector(QtWidgets.QGroupBox):
    def __init__(self, parent=None):
        super(HandlerSelector, self).__init__("Trace Event Processors", parent)
        self.setFlat(True)
        box = QtWidgets.QVBoxLayout(self)
        self.options = {}
        for name in trace.handlers:
            btn = QtWidgets.QCheckBox(name)
            btn.setToolTip(trace.handlers[name].__doc__)
            box.addWidget(btn)
            self.options[name] = btn
        box.addStretch(1)
        self.setCheckable(True)
        self.setChecked(True)
        self.setLayout(box)


class MachineSelector(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(MachineSelector, self).__init__(parent)
        box = QtWidgets.QHBoxLayout(self)
        label = MonitoringLabel('List of &machines (threads)')
        self.is_ready = label.is_ready
        self.updated = label.updated
        box.addWidget(label)
        self._machines = QtWidgets.QLineEdit('all')
        self._machines.setToolTip('an integer, \
        a comma-separated list of integers, or "all"')
        grammar = QRegExp(r'\s*(all|\d+\s*(,\s*\d+\s*)*)\s*')
        valid = QtGui.QRegExpValidator(grammar)
        self._machines.setValidator(valid)
        label.setBuddy(self._machines)
        box.addWidget(self._machines)
        box.addStretch(1)
        self.setLayout(box)

    def selected(self):
        if not self._machines.hasAcceptableInput():
            raise ValueError('invalid input')
        data = self._machines.text().strip()
        if data == 'all':
            return None
        else:
            return [int(x) for x in data.split(',')]


class MonitoringLabel(QtWidgets.QLabel):
    "a label that will monitors the validity of its buddy"

    updated = pyqtSignal()

    def __init__(self, text='', buddy=None, parent=None):
        super(MonitoringLabel, self).__init__(parent)
        self.setText(text)
        if buddy:
            self.setBuddy(buddy)

    def setText(self, text):
        super(MonitoringLabel, self).setText(text)
        self.text = text

    def setBuddy(self, buddy):
        super(MonitoringLabel, self).setBuddy(buddy)
        buddy.textChanged.connect(lambda x: self.update())
        self.update()

    def is_ready(self):
        return not self.buddy() or self.buddy().hasAcceptableInput()

    def update(self):
        self.updated.emit()
        if self.is_ready():
            super(MonitoringLabel, self).setText(self.text)
        else:
            super(MonitoringLabel, self).setText(
                '<font color=red>'+self.text+'</font>')


class ExistingFileValidator(QtGui.QValidator):
    def __init__(self, parent=None):
        super(ExistingFileValidator, self).__init__(parent)

    def validate(self, name, pos):
        if os.path.isfile(name):
            return (self.Acceptable, name, pos)
        else:
            return (self.Intermediate, name, pos)


class TraceFileSelector(QtWidgets.QWidget):

    def __init__(self, parent=None):
        super(TraceFileSelector, self).__init__(parent)
        box = QtWidgets.QHBoxLayout(self)
        label = MonitoringLabel('Trace &file:')
        self.is_ready = label.is_ready
        self.updated = label.updated
        box.addWidget(label)
        self.location = QtWidgets.QLineEdit('incidents')
        self.text = self.location.text
        must_exist = ExistingFileValidator()
        self.location.setValidator(must_exist)
        label.setBuddy(self.location)
        box.addWidget(self.location)
        openfile = QtWidgets.QPushButton(self)
        openfile.setIcon(self.style().standardIcon(
            QtWidgets.QStyle.SP_DialogOpenButton))
        dialog = QtWidgets.QFileDialog(self)
        openfile.clicked.connect(dialog.open)
        dialog.fileSelected.connect(self.location.setText)
        box.addWidget(openfile)
        box.addStretch(1)
        self.setLayout(box)


class IncidentView(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(IncidentView, self).__init__(parent)
        self.view = QtWidgets.QTreeView()
        self.view.setAllColumnsShowFocus(True)
        self.view.setUniformRowHeights(True)
        box = QtWidgets.QVBoxLayout()
        box.addWidget(self.view)
        self.load_trace = QtWidgets.QPushButton('&Trace')
        self.load_trace.setToolTip('Load into the Trace Window')
        self.load_trace.setEnabled(False)
        for activation_signal in [
                self.view.activated,
                self.view.entered,
                self.view.pressed]:
            activation_signal.connect(lambda _: self.update_controls_state())
        self.load_trace.clicked.connect(self.load_current_trace)
        self.view.doubleClicked.connect(self.jump_to_index)
        hbox = QtWidgets.QHBoxLayout()
        self.filter = QtWidgets.QLineEdit()
        self.filter.textChanged.connect(self.filter_model)
        filter_label = QtWidgets.QLabel('&Search')
        filter_label.setBuddy(self.filter)
        hbox.addWidget(filter_label)
        hbox.addWidget(self.filter)
        hbox.addWidget(self.load_trace)
        box.addLayout(hbox)
        self.setLayout(box)
        self.model = None
        self.proxy = None

    def display(self, incidents, locations):
        self.model = IncidentModel(incidents, locations, self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterRole(self.model.filter_role)
        self.proxy.setFilterRegExp(QRegExp(self.filter.text()))
        self.view.setModel(self.proxy)

    def filter_model(self, txt):
        if self.proxy:
            self.proxy.setFilterRegExp(QRegExp(txt))

    def update_controls_state(self):
        curr = self.view.currentIndex()
        self.load_trace.setEnabled(curr.isValid() and
                                   curr.parent().isValid())

    def load_current_trace(self):
        idx = self.proxy.mapToSource(self.view.currentIndex())
        if not idx.isValid() or index_level(idx) not in (1, 2):
            raise ValueError('load_current_trace: invalid index')

        if index_level(idx) == 2:
            idx = idx.parent()

        incident = self.model.incidents[idx.parent().row()]
        location = incident.locations[idx.row()]
        backtrace = self.model.locations[location]

        for p in reversed(backtrace):
            self.load_trace_point(p)

    def jump_to_index(self, idx):
        idx = self.proxy.mapToSource(idx)
        if index_level(idx) != 2:
            # don't mess with parents, they are used to create children
            return
        grandpa = idx.parent().parent()
        incident = self.model.incidents[grandpa.row()]
        location = incident.locations[idx.parent().row()]
        trace = self.model.locations[location]
        point = trace[idx.row()]
        self.show_trace_point(point)

    def load_trace_point(self, p):
        add_insn_to_trace_view(p.addr)

    def show_trace_point(self, p):
        idaapi.jumpto(p.addr)


class TraceLoaderController(QtWidgets.QWidget):
    finished = pyqtSignal()

    def __init__(self, parent=None):
        super(TraceLoaderController, self).__init__(parent)
        self.loader = None
        box = QtWidgets.QVBoxLayout(self)
        self.location = TraceFileSelector(self)
        self.handlers = HandlerSelector(self)
        self.machines = MachineSelector(self)
        box.addWidget(self.location)
        box.addWidget(self.handlers)
        box.addWidget(self.machines)
        self.load = QtWidgets.QPushButton('&Load')
        self.load.setDefault(True)
        self.load.setEnabled(self.location.is_ready())
        self.cancel = QtWidgets.QPushButton('&Stop')
        self.cancel.setVisible(False)
        hor = QtWidgets.QHBoxLayout()
        hor.addWidget(self.load)
        hor.addWidget(self.cancel)
        self.progress = QtWidgets.QProgressBar()
        self.progress.setVisible(False)
        hor.addWidget(self.progress)
        hor.addStretch(2)
        box.addLayout(hor)

        def enable_load():
            self.load.setEnabled(self.location.is_ready() and
                                 self.machines.is_ready())
        self.location.updated.connect(enable_load)
        self.machines.updated.connect(enable_load)
        enable_load()
        self.processor = QTimer()
        self.processor.timeout.connect(self.process)
        self.load.clicked.connect(self.processor.start)
        self.cancel.clicked.connect(self.stop)
        self.setLayout(box)

    def start(self):
        self.cancel.setVisible(True)
        self.load.setVisible(False)
        filename = self.location.text()
        self.loader = trace.Loader(file(filename))
        self.progress.setVisible(True)
        stat = os.stat(filename)
        self.progress.setRange(0, stat.st_size)
        machines = self.machines.selected()
        if machines is not None:
            self.loader.enable_filter('filter-machine', id=machines)

        for name in self.handlers.options:
            if self.handlers.options[name].isChecked():
                self.loader.enable_handlers([name])

    def stop(self):
        self.processor.stop()
        self.progress.setVisible(False)
        self.cancel.setVisible(False)
        self.load.setVisible(True)
        self.loader = None
        self.finished.emit()

    def process(self):
        if not self.loader:
            self.start()
        try:
            self.loader.next()
            self.progress.setValue(self.loader.parser.lexer.instream.tell())
        except StopIteration:
            self.stop()


def index_level(idx):
    if idx.isValid():
        return 1 + index_level(idx.parent())
    else:
        return -1


def index_up(idx, level=0):
    if level == 0:
        return idx
    else:
        return index_up(idx.parent(), level=level-1)


class IncidentIndex(object):
    def __init__(self, model, index):
        self.model = model
        self.index = index

    @property
    def incidents(self):
        return self.model.incidents

    @property
    def level(self):
        return index_level(self.index)

    @property
    def column(self):
        return self.index.column()

    @property
    def row(self):
        return self.index.row()

    @property
    def incident(self):
        top = index_up(self.index, self.level)
        return self.incidents[top.row()]

    @property
    def location(self):
        if self.level in (1, 2):
            top = self.index
            if self.level == 2:
                top = index_up(self.index, 1)
            location_id = self.incident.locations[top.row()]
            if self.model.locations is None:
                return None
            else:
                return self.model.locations.get(location_id)

    @property
    def point(self):
        if self.level == 2:
            return self.location[self.index.row()]


class IncidentModel(QAbstractItemModel):
    filter_role = Qt.UserRole
    sort_role = Qt.UserRole + 1

    handlers = []

    def __init__(self, incidents, locations, parent=None):
        super(IncidentModel, self).__init__(parent)
        self.incidents = incidents
        self.locations = locations
        self.parents = {0: QModelIndex()}
        self.child_ids = 0

    def dispatch(self, role, index):
        for handler in self.handlers:
            def sat(c, v):
                if c == 'roles':
                    return role in v
                if c == 'level':
                    return index.level == v
                if c == 'column':
                    return index.column == v

            for (c, v) in handler['constraints'].items():
                if not sat(c, v):
                    break
            else:
                return handler['accept'](index)

    def index(self, row, col, parent):
        if parent.isValid():
            self.child_ids += 1
            index = self.createIndex(row, col, self.child_ids)
            self.parents[self.child_ids] = parent
            return index
        else:
            return self.createIndex(row, col, 0)

    def parent(self, child):
        return self.parents[child.internalId()]

    def rowCount(self, parent):
        n = self.dispatch('row-count', IncidentIndex(self, parent))
        return 0 if n is None else n

    def columnCount(self, parent):
        return 2 if not parent.isValid() or parent.column() == 0 else 0

    def data(self, index, role):
        role = {
            Qt.DisplayRole: 'display',
            self.sort_role: 'sort',
            self.filter_role: 'filter'
        }.get(role)

        if role:
            return QVariant(self.dispatch(role, IncidentIndex(self, index)))
        else:
            return QVariant()


def defmethod(*args, **kwargs):
    def register(method):
        kwargs['roles'] = args
        IncidentModel.handlers.append({
            'name': method.__name__,
            'constraints': kwargs,
            'accept': method})
    return register


@defmethod('display', level=2, column=0)
def display_point(msg):
    return '{:x}'.format(msg.point.addr)


@defmethod('display', level=2, column=1)
def display_point_machine(msg):
    return msg.point.machine


@defmethod('display', level=1, column=0)
def display_incident_location(msg):
    return 'location-{}'.format(msg.row)


@defmethod('display', level=0, column=0)
def display_incident_name(msg):
    return msg.incident.name


@defmethod('display', level=0, column=1)
def display_incident_id(msg):
    return msg.row


@defmethod('sort', 'filter', column=0)
def incident_name(msg):
    return msg.incident.name


@defmethod('row-count', level=-1)
def number_of_incidents(msg):
    return len(msg.incidents)


@defmethod('row-count', level=0, column=0)
def number_of_locations(msg):
    return len(msg.incident.locations)


@defmethod('row-count', level=1, column=0)
def backtrace_length(msg):
    return 0 if msg.location is None else len(msg.location)


class Incident(object):
    __slots__ = ['name', 'locations']

    def __init__(self, name, locations):
        self.name = name
        self.locations = locations

    def __repr__(self):
        return 'Incident({}, {})'.format(repr(self.name),
                                         repr(self.locations))


class Point(object):
    __slots__ = ['addr', 'machine']

    def __init__(self, addr, machine=None):
        self.addr = addr
        self.machine = machine

    def __str__(self):
        if self.machine:
            return '{}:{}'.format(self.machine, self.addr)
        else:
            return str(self.addr)

    def __repr__(self):
        if self.machine:
            return 'Point({},{})'.format(self.machine, self.addr)
        else:
            return 'Point({})'.format(repr(self.addr))


def parse_point(data):
    parts = data.split(':')
    if len(parts) == 1:
        return Point(int(data, 16))
    else:
        return Point(int(parts[1], 16), int(parts[0]))


class BapTraceMain(idaapi.PluginForm):
    def OnCreate(self, form):
        form = self.FormToPyQtWidget(form)
        self.control = TraceLoaderController(form)
        self.incidents = IncidentView(form)

        def display():
            self.incidents.display(incidents, locations)
        self.control.finished.connect(display)
        box = QtWidgets.QHBoxLayout()
        split = QtWidgets.QSplitter()
        split.addWidget(self.control)
        split.addWidget(self.incidents)
        box.addWidget(split)
        form.setLayout(box)


class BapTracePlugin(idaapi.plugin_t):
    wanted_name = 'BAP: Load Observations'
    wanted_hotkey = ''
    flags = 0
    comment = 'Load Primus Observations'
    help = """
    Loads Primus Observations into IDA for further analysis
    """

    def __init__(self):
        self.form = None
        self.name = 'Primus Observations'

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        if not self.form:
            self.form = BapTraceMain()
        return self.form.Show(self.name, options=(
            self.form.FORM_PERSIST |
            self.form.FORM_SAVE))


def PLUGIN_ENTRY():
    return BapTracePlugin()


main = None


def bap_trace_test():
    global main
    main = BapTraceMain()
    main.Show('Primus Observations')
