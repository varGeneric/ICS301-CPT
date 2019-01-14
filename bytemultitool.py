import sys
from crc8 import crc8
import crcmod
import crcmod.predefined
from binascii import crc32
from hashlib import md5, sha1, sha256, sha512
from PySide2.QtCore import Qt, QEvent, Slot
#from PySide2.QtGui import QFocusEvent
from PySide2.QtWidgets import (
    QAction,
    QApplication,
    QBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMenuBar,
    QWidget
)

# Global things
app = QApplication([])
window = QWidget()
layout = QGridLayout(window)
menu_bar = QMenuBar(window)
raw_hex = QLineEdit(window)
raw_hex_label = QLabel("Raw Hex")
little_endian = QLineEdit(window)
little_endian_label = QLabel("Little Endian")
big_endian = QLineEdit(window)
big_endian_label = QLabel("Big Endian")
encoded_text = QLineEdit(window)
encoded_text_label = QLabel("Encoded Text")
file_menu = menu_bar.addMenu("&File")

test_action = QAction("&Test")


# User interaction event handlers
@Slot()
def testClick():
    print("clicked")

def register_edit_events():
    # raw_hex.focusOutEvent(test_edit)

def add_widgets_to_layout():
    layout.addWidget(raw_hex_label)
    layout.addWidget(raw_hex)
    layout.addWidget(little_endian_label)
    layout.addWidget(little_endian)
    layout.addWidget(big_endian_label)
    layout.addWidget(big_endian)
    layout.addWidget(encoded_text_label)
    layout.addWidget(encoded_text)
    
    window.setLayout(layout)

test_action.triggered.connect(testClick)
file_menu.addAction(test_action)

add_widgets_to_layout()
window.setWindowTitle("The Byte Multitool")
window.resize(600, 600)
window.showNormal()

print(crc8(b"hello world").hexdigest())
print()

app.exec_()
