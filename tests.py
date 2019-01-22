import bytemultitool
from hashlib import md5, sha1, sha256

assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    0x86fb269d190d2c85f6e0468ceca42a20
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    0xd3486ae9136e7856bc42212385ea797094475802
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    0xc0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a
