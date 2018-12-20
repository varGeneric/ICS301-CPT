import sys
from PySide2.QtCore import Qt, Slot
# from PySide2.QtGui import QPainter, QPaintDevice
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
file_menu = menubar.addMenu("&File")

test_action = QAction("&Test")
test_action.triggered.connect(testClick)


# User interaction event handlers
@Slot()
def testClick():
    print("clicked")

filemenu.addAction(test_action)

window.setLayout(layout)
window.setWindowTitle("The Byte Multitool")
window.resize(600, 600)
window.showNormal()

app.exec_()
