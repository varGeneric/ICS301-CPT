import sys
from binascii import crc32, unhexlify, Error
from hashlib import md5, sha1, sha256

from PySide2.QtCore import Qt, Slot
from PySide2.QtWidgets import (QAction, QApplication, QBoxLayout, QGridLayout,
                               QLabel, QLineEdit, QMenuBar, QWidget, QComboBox)

# Text encodings that can be displayed
TEXT_ENCODINGS_STRINGS = ["ASCII", "UTF-8", "UTF-16", "UTF-32", "Big5"]

# Global things
app = QApplication([])
window = QWidget()
layout = QBoxLayout(QBoxLayout.TopToBottom)
menu_bar = QMenuBar(window)

raw_hex = QLineEdit(window)
raw_hex_label = QLabel("Raw Hex")
raw_hex_layout = QBoxLayout(QBoxLayout.TopToBottom)

little_endian = QLineEdit(window)
little_endian_label = QLabel("Little Endian")
little_endian_layout = QBoxLayout(QBoxLayout.TopToBottom)

big_endian = QLineEdit(window)
big_endian_label = QLabel("Big Endian")
big_endian_layout = QBoxLayout(QBoxLayout.TopToBottom)

encoded_text = QLineEdit(window)
encoded_text_label = QLabel("Encoded Text")
encoded_text_layout = QBoxLayout(QBoxLayout.TopToBottom)
text_encodings_menu = QComboBox()

hashes_layout = QGridLayout()
hash_md5 = QLabel("MD5: ")
hash_sha1 = QLabel("SHA1: ")
hash_sha256 = QLabel("SHA256: ")
hash_crc32 = QLabel("CRC32: ")

file_menu = menu_bar.addMenu("&File")

test_action = QAction("&Test")
info_action = QAction("&Info")
quit_action = QAction("&Quit")


# User interaction event handlers
@Slot()
def testClick():
    print("clicked")


@Slot()
def raw_hex_edit():
    try:
        # 0x prefix
        if len(raw_hex.text()) > 2 and raw_hex.text()[1] == 'x':
            update_fields(unhexlify(raw_hex.text()[2:]))
        # No prefix
        else:
            update_fields(unhexlify(raw_hex.text()))
    except Error:
        little_endian.clear()
        big_endian.clear()
        encoded_text.clear()


@Slot()
def little_endian_edit():
    pass


@Slot()
def big_endian_edit():
    pass


@Slot()
def encoded_text_edit():
    update_fields(encoded_text.text().encode(
        TEXT_ENCODINGS_STRINGS[text_encodings_menu.currentIndex()].lower(),
        'strict'
        )
    )


def update_fields(binary_data):
    # Update raw hex field
    raw_hex.setText("0x" + hex(
        int.from_bytes(binary_data, byteorder='big', signed=False)
        )[2:].upper())  # Take substring from afer 0x and make it uppercase

    # Update little endian field
    little_endian.setText("0x" + hex(
        int.from_bytes(binary_data, byteorder='little', signed=False)
        )[2:].upper())

    # Update encoded text field
    try:
        encoded_text.setText(
            binary_data.decode(
                TEXT_ENCODINGS_STRINGS[
                    text_encodings_menu.currentIndex()
                    ].lower(),
                'strict'
                )
        )
    except UnicodeDecodeError:
        encoded_text.setText("Invalid character in string. ")

    # Update hashes
    md5_generator = md5()
    md5_generator.update(binary_data)
    hash_md5.setText("MD5: " + md5_generator.hexdigest())

    sha1_generator = sha1()
    sha1_generator.update(binary_data)
    hash_sha1.setText("SHA1: " + sha1_generator.hexdigest())

    sha256_generator = sha256()
    sha256_generator.update(binary_data)
    hash_sha256.setText("SHA256: " + sha256_generator.hexdigest())

    crc32_generator = crc32()
    crc32_generator.update(binary_data)
    hash_crc32.setText("CRC32: " + crc32_generator.hexdigest())

    # Not implementing because 512 byte hashes take up a ton of window space
    # And are pretty much never used
    # sha512_generator = sha512()
    # sha512_generator.update(binary_data)
    # hash_sha512.setText("SHA512: " + sha512_generator.hexdigest())


def register_menu_events():
    test_action.triggered.connect(testClick)
    quit_action.triggered.connect(app.quit)

    file_menu.addAction(test_action)
    file_menu.addAction(info_action)
    file_menu.addAction(quit_action)


def register_edit_events():
    raw_hex.textEdited.connect(raw_hex_edit)
    encoded_text.textEdited.connect(encoded_text_edit)


def add_widgets_to_layout():
    # 32 characters plu label
    hash_md5.setMinimumWidth(37*6)
    hashes_layout.addWidget(hash_md5, 0, 0)
    hashes_layout.addWidget(hash_sha1, 0, 1)
    hashes_layout.addWidget(hash_sha256, 1, 0)
    hashes_layout.addWidget(hash_crc32, 1, 1)

    raw_hex_layout.addWidget(raw_hex_label)
    raw_hex_layout.addWidget(raw_hex)
    raw_hex_layout.setAlignment(Qt.AlignCenter)

    little_endian_layout.addWidget(little_endian_label)
    little_endian_layout.addWidget(little_endian)
    little_endian_layout.setAlignment(Qt.AlignCenter)

    big_endian_layout.addWidget(big_endian_label)
    big_endian_layout.addWidget(big_endian)
    big_endian_layout.setAlignment(Qt.AlignCenter)

    encoded_text_layout.addWidget(encoded_text_label)
    encoded_text_layout.addWidget(encoded_text)
    encoded_text_layout.setAlignment(Qt.AlignCenter)

    text_encodings_menu.addItems(TEXT_ENCODINGS_STRINGS)

    # Give the menu bar a static height, looks bad when it resizes
    menu_bar.setFixedHeight(20)
    # Give the dropdown a fixed width, looks odd streched
    text_encodings_menu.setFixedWidth(120)

    layout.addWidget(menu_bar)

    layout.addWidget(text_encodings_menu)
    layout.addLayout(raw_hex_layout)
    layout.addLayout(little_endian_layout)
    layout.addLayout(big_endian_layout)
    layout.addLayout(encoded_text_layout)
    layout.addLayout(hashes_layout)

    window.setLayout(layout)


def set_window_properties():
    window.setWindowTitle("The Byte Multitool")
    window.resize(600, 350)
    window.showNormal()


def main():
    add_widgets_to_layout()
    register_edit_events()
    register_menu_events()
    set_window_properties()

    print()

    app.exec_()


main()
