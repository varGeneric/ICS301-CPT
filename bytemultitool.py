import platform
import sys
from binascii import Error, crc32, unhexlify
from hashlib import md5, sha1, sha256

from PySide2.QtCore import Qt, Slot
from PySide2.QtWidgets import (QAction, QApplication, QBoxLayout, QComboBox,
                               QDialog, QGridLayout, QLabel, QLineEdit,
                               QMenuBar, QWidget)

# Text encodings that can be displayed
TEXT_ENCODINGS_STRINGS = ["ASCII", "UTF-8", "UTF-16", "UTF-32", "Big5"]

# Global things
app = QApplication([])
window = QWidget()
layout = QGridLayout(window)
menu_bar = QMenuBar(window)

raw_hex = QLineEdit(window)
raw_hex_label = QLabel("Raw Hex")
raw_hex_layout = QBoxLayout(QBoxLayout.TopToBottom)

little_endian = QLineEdit(window)
little_endian_label = QLabel("Little Endian")
little_endian_layout = QBoxLayout(QBoxLayout.TopToBottom)

encoded_text = QLineEdit(window)
encoded_text_label = QLabel("Encoded Text")
encoded_text_layout = QBoxLayout(QBoxLayout.TopToBottom)
text_encodings_menu = QComboBox()

hash_md5 = QLabel("MD5: ")
hash_sha1 = QLabel("SHA1: ")
hash_sha256 = QLabel("SHA256: ")
hash_crc32 = QLabel("CRC32: ")

uint8_field = QLineEdit(window)
uint8_label = QLabel("uINT8")
uint8_layout = QBoxLayout(QBoxLayout.TopToBottom)

int8_field = QLineEdit(window)
int8_label = QLabel("INT8")
int8_layout = QBoxLayout(QBoxLayout.TopToBottom)

uint16_field = QLineEdit(window)
uint16_label = QLabel("uINT16")
uint16_layout = QBoxLayout(QBoxLayout.TopToBottom)

int16_field = QLineEdit(window)
int16_label = QLabel("INT16")
int16_layout = QBoxLayout(QBoxLayout.TopToBottom)

uint32_field = QLineEdit(window)
uint32_label = QLabel("uINT32")
uint32_layout = QBoxLayout(QBoxLayout.TopToBottom)

int32_field = QLineEdit(window)
int32_label = QLabel("INT32")
int32_layout = QBoxLayout(QBoxLayout.TopToBottom)

file_menu = menu_bar.addMenu("&File")

info_action = QAction("&Info")
quit_action = QAction("&Quit")


# User interaction event handlers
@Slot()
def display_sys_info():
    sys_info_window = QDialog()
    sys_info_layout = QGridLayout(window)
    sys_info_platform_layout = QBoxLayout(QBoxLayout.TopToBottom)

    # Iterate through basic uname info
    for attrib in platform.uname():
        sys_info_platform_layout.addWidget(QLabel(attrib))

    sys_info_layout.addWidget(QLabel("System Endianness: " + sys.byteorder))
    sys_info_layout.addWidget(
        QLabel("System Encoding: " + sys.getfilesystemencoding())
        )
    sys_info_layout.addWidget(
        QLabel("Python " + platform.python_version()), 4, 0
        )

    sys_info_layout.addLayout(sys_info_platform_layout, 3, 0)
    sys_info_window.setLayout(sys_info_layout)
    sys_info_window.setWindowTitle("System Info")
    sys_info_window.exec()


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
        encoded_text.clear()


@Slot()
def little_endian_edit():
    try:
        # 0x prefix
        if len(raw_hex.text()) > 2 and raw_hex.text()[1] == 'x':
            update_fields(unhexlify(raw_hex.text()[2:]))
        # No prefix
        else:
            update_fields(unhexlify(raw_hex.text()))
    except Error:
        raw_hex.clear()
        encoded_text.clear()


@Slot()
def encoded_text_edit():
    update_fields(encoded_text.text().encode(
        TEXT_ENCODINGS_STRINGS[text_encodings_menu.currentIndex()].lower(),
        'strict'
        )
    )


@Slot()
def uint8_edit():
    try:
        # HACK: remove 0x prefix from hex() with substring
        value = hex(int(uint8_field.text()) & 0xFF)[2:]
    except ValueError:
        update_fields(b'\00')
    else:
        # HACK: unhexlify only takes even length strings, pad a 0 if odd length
        update_fields(unhexlify('0' * (len(value) % 2) + value))


@Slot()
def int8_edit():
    try:
        # HACK: remove 0x prefix from hex() with substring
        value = hex(int(int8_field.text()) & 0xFF)[2:]
    except ValueError:
        update_fields(b'\00')
    else:
        # HACK: unhexlify only takes even length strings, pad a 0 if odd length
        update_fields(unhexlify('0' * (len(value) % 2) + value))


@Slot()
def uint16_edit():
    try:
        # HACK: remove 0x prefix from hex() with substring
        value = hex(int(uint16_field.text()) & 0xFFFF)[2:]
    except ValueError:
        update_fields(b'\00')
    else:
        # HACK: unhexlify only takes even length strings, pad a 0 if odd length
        update_fields(unhexlify('0' * (len(value) % 2) + value))


@Slot()
def int16_edit():
    try:
        # HACK: remove 0x prefix from hex() with substring
        value = hex(int(int16_field.text()) & 0xFFFF)[2:]
    except ValueError:
        update_fields(b'\00')
    else:
        # HACK: unhexlify only takes even length strings, pad a 0 if odd length
        update_fields(unhexlify('0' * (len(value) % 2) + value))


@Slot()
def uint32_edit():
    try:
        # HACK: remove 0x prefix from hex() with substring
        value = hex(int(uint32_field.text()) & 0xFFFFFFFF)[2:]
    except ValueError:
        update_fields(b'\00')
    else:
        # HACK: unhexlify only takes even length strings, pad a 0 if odd length
        update_fields(unhexlify('0' * (len(value) % 2) + value))


@Slot()
def int32_edit():
    try:
        # HACK: remove 0x prefix from hex() with substring
        value = hex(int(int32_field.text()) & 0xFFFFFFFF)[2:]
    except ValueError:
        update_fields(b'\00')
    else:
        # HACK: unhexlify only takes even length strings, pad a 0 if odd length
        update_fields(unhexlify('0' * (len(value) % 2) + value))


def get_data_hash(binary_data, hash_algo=md5):
    hash_generator = hash_algo()
    hash_generator.update(binary_data)
    return hash_generator.hexdigest()


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
    except (UnicodeDecodeError, ValueError):
        encoded_text.setText("Invalid character in string. ")

    # Update hashes
    hash_md5.setText("MD5: " + get_data_hash(binary_data, md5))
    hash_sha1.setText("SHA1: " + get_data_hash(binary_data, sha1))
    hash_sha256.setText("SHA256: " + get_data_hash(binary_data, sha256))
    # CRC uses a different library
    hash_crc32.setText("CRC32: " + hex(crc32(binary_data))[2:])

    # Not implementing because 512 byte hashes take up a ton of window space
    # And are pretty much never used
    # sha512_generator = sha512()
    # sha512_generator.update(binary_data)
    # hash_sha512.setText("SHA512: " + sha512_generator.hexdigest())

    # Update integer representations
    uint8_field.setText(str(int.from_bytes(
        binary_data, byteorder='big', signed=False) & 0xFF))
    int8_field.setText(str(int.from_bytes(
        binary_data, byteorder='big', signed=True) & 0x7F))
    uint16_field.setText(str(int.from_bytes(
        binary_data, byteorder='big', signed=False) & 0xFFFF))
    int16_field.setText(str(int.from_bytes(
        binary_data, byteorder='big', signed=True) & 0x7FFF))
    uint32_field.setText(str(int.from_bytes(
        binary_data, byteorder='big', signed=False) & 0xFFFFFFFF))
    int32_field.setText(str(int.from_bytes(
        binary_data, byteorder='big', signed=True) & 0x7FFFFFFF))


def register_menu_events():
    quit_action.triggered.connect(app.quit)
    info_action.triggered.connect(display_sys_info)

    file_menu.addAction(info_action)
    file_menu.addAction(quit_action)


def register_edit_events():
    raw_hex.textEdited.connect(raw_hex_edit)
    little_endian.textEdited.connect(little_endian_edit)
    encoded_text.textEdited.connect(encoded_text_edit)

    uint8_field.textEdited.connect(uint8_edit)
    int8_field.textEdited.connect(int8_edit)
    uint16_field.textEdited.connect(uint16_edit)
    int16_field.textEdited.connect(int16_edit)
    uint32_field.textEdited.connect(uint32_edit)
    int32_field.textEdited.connect(int32_edit)

    text_encodings_menu.currentIndexChanged.connect(encoded_text_edit)

    hash_crc32.setTextInteractionFlags(Qt.TextSelectableByMouse)
    hash_md5.setTextInteractionFlags(Qt.TextSelectableByMouse)
    hash_sha1.setTextInteractionFlags(Qt.TextSelectableByMouse)
    hash_sha256.setTextInteractionFlags(Qt.TextSelectableByMouse)


def add_widgets_to_layout():
    # 32 characters plus label
    hash_md5.setMinimumWidth(37*6)

    raw_hex_layout.addWidget(raw_hex_label)
    raw_hex_layout.addWidget(raw_hex)
    raw_hex_layout.setAlignment(Qt.AlignCenter)

    little_endian_layout.addWidget(little_endian_label)
    little_endian_layout.addWidget(little_endian)
    little_endian_layout.setAlignment(Qt.AlignCenter)

    encoded_text_layout.addWidget(encoded_text_label)
    encoded_text_layout.addWidget(encoded_text)
    encoded_text_layout.setAlignment(Qt.AlignCenter)

    uint8_layout.addWidget(uint8_label)
    uint8_layout.addWidget(uint8_field)
    uint8_layout.setAlignment(Qt.AlignCenter)

    int8_layout.addWidget(int8_label)
    int8_layout.addWidget(int8_field)
    int8_layout.setAlignment(Qt.AlignCenter)

    uint16_layout.addWidget(uint16_label)
    uint16_layout.addWidget(uint16_field)
    uint16_layout.setAlignment(Qt.AlignCenter)

    int16_layout.addWidget(int16_label)
    int16_layout.addWidget(int16_field)
    int16_layout.setAlignment(Qt.AlignCenter)

    uint32_layout.addWidget(uint32_label)
    uint32_layout.addWidget(uint32_field)
    uint32_layout.setAlignment(Qt.AlignCenter)

    int32_layout.addWidget(int32_label)
    int32_layout.addWidget(int32_field)
    int32_layout.setAlignment(Qt.AlignCenter)

    text_encodings_menu.addItems(TEXT_ENCODINGS_STRINGS)

    # Give the menu bar a static height, looks bad when it resizes
    # Fixed by adding as menubar for layout, ensures not resized
    # menu_bar.setFixedHeight(35)

    # Make menu bar native style, looks much better
    menu_bar.setNativeMenuBar(True)
    # Give the dropdown a fixed width, looks odd streched
    text_encodings_menu.setFixedWidth(120)

    layout.setMenuBar(menu_bar)

    layout.addWidget(text_encodings_menu, 1, 0)
    layout.addLayout(raw_hex_layout, 2, 0)
    layout.addLayout(little_endian_layout, 3, 0)
    layout.addLayout(encoded_text_layout, 4, 0)
    layout.addLayout(uint8_layout, 5, 0)
    layout.addLayout(int8_layout, 5, 1)
    layout.addLayout(uint16_layout, 6, 0)
    layout.addLayout(int16_layout, 6, 1)
    layout.addLayout(uint32_layout, 7, 0)
    layout.addLayout(int32_layout, 7, 1)
    layout.addWidget(hash_md5, 8, 0)
    layout.addWidget(hash_crc32, 9, 0)
    layout.addWidget(hash_sha1, 8, 1)
    layout.addWidget(hash_sha256, 9, 1)

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

    app.exec_()


if __name__ == "__main__":
    main()
