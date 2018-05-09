import idaapi

import os


from bap.utils import trace
from PyQt5 import QtWidgets
from PyQt5 import QtGui

from PyQt5.QtCore import (
    QFile,
    QIODevice,
    QCryptographicHash as QCrypto,
    QRegExp,
    QTimer,
    pyqtSignal)


@trace.handler('pc-changed', requires=['machine-id', 'pc'])
def tev_insn(state, ev):
    "stores each visted instruction to the IDA Trace Window"
    idaapi.dbg_add_tev(1, state['machine-id'], state['pc'])


@trace.handler('call', requires=['machine-id', 'pc'])
def tev_call(state, call):
    "stores call events to the IDA Trace Window"
    caller = state['pc']
    callee = idaapi.get_name_ea(0, call[0])
    idaapi.dbg_add_call_tev(state['machine-id'], caller, callee)


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


class TraceLoaderController(object):
    def __init__(self, parent):
        self.loader = None
        box = QtWidgets.QVBoxLayout(parent)
        self.location = TraceFileSelector(parent)
        self.handlers = HandlerSelector(parent)
        self.machines = MachineSelector(parent)
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
        parent.setLayout(box)

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

    def process(self):
        if not self.loader:
            self.start()
        try:
            self.loader.next()
            self.progress.setValue(self.loader.parser.lexer.instream.tell())
        except StopIteration:
            self.stop()


class BapTraceMain(idaapi.PluginForm):
    def OnCreate(self, form):
        parent = self.FormToPyQtWidget(form)
        self.control = TraceLoaderController(parent)


def bap_trace_test():
    main = BapTraceMain()
    main.Show('Primus Observations')
