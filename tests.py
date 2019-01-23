import bytemultitool
from hashlib import md5, sha1, sha256

# MD5 hash tests
assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    "86fb269d190d2c85f6e0468ceca42a20"
assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    "86fb269d190d2c85f6e0468ceca42a20"
assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    "86fb269d190d2c85f6e0468ceca42a20"
assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    "86fb269d190d2c85f6e0468ceca42a20"
assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    "86fb269d190d2c85f6e0468ceca42a20"

# SHA1 hash tests
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    "d3486ae9136e7856bc42212385ea797094475802"
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    "d3486ae9136e7856bc42212385ea797094475802"
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    "d3486ae9136e7856bc42212385ea797094475802"
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    "d3486ae9136e7856bc42212385ea797094475802"
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    "d3486ae9136e7856bc42212385ea797094475802"

# SHA256 hash tests
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a"
