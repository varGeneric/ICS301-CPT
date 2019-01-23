import bytemultitool
from hashlib import md5, sha1, sha256

# MD5 hash tests
assert bytemultitool.get_data_hash(b"Hello world!", md5) == \
    "86fb269d190d2c85f6e0468ceca42a20", "MD5 hash incorrect"
assert bytemultitool.get_data_hash(b"I <3 CS", md5) == \
    "01fb95043765e498763e0a7ae5762039", "MD5 hash incorrect"
assert bytemultitool.get_data_hash(b"Literally any string", md5) == \
    "1078f9bdbcd36d2e3d2ff96f8b6507da", "MD5 hash incorrect"
assert bytemultitool.get_data_hash(b"can be used here.", md5) == \
    "a128fd5155d67c7362ee9e389b989f21", "MD5 hash incorrect"
assert bytemultitool.get_data_hash(b"5 tests might be excessive", md5) == \
    "81695d93f6a33f62ad8d2e38c817eb87", "MD5 hash incorrect"

# SHA1 hash tests
assert bytemultitool.get_data_hash(b"Hello world!", sha1) == \
    "d3486ae9136e7856bc42212385ea797094475802", "SHA1 hash incorrect"
assert bytemultitool.get_data_hash(b"I <3 CS", sha1) == \
    "f951e4aabbedf4b4cd4fb355da1441001284611f", "SHA1 hash incorrect"
assert bytemultitool.get_data_hash(b"Literally any string", sha1) == \
    "c6acb9a6b4864cb62141810a0aea8e05d2562e21", "SHA1 hash incorrect"
assert bytemultitool.get_data_hash(b"can be used here.", sha1) == \
    "23d2b639f4b7f1265ae572ae9ba4b41ad63501c9", "SHA1 hash incorrect"
assert bytemultitool.get_data_hash(b"5 tests might be excessive", sha1) == \
    "aa8b354fdf6e8da7cb21d9665a36243294aae105", "SHA1 hash incorrect"

# SHA256 hash tests
assert bytemultitool.get_data_hash(b"Hello world!", sha256) == \
    "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a", \
    "SHA256 hash incorrect"
assert bytemultitool.get_data_hash(b"I <3 CS", sha256) == \
    "eb349646327a2f7d9021824543b7f3cad9e51585c4ac59770a570e4e58042aca", \
    "SHA256 hash incorrect"
assert bytemultitool.get_data_hash(b"Literally any string", sha256) == \
    "042f26df611d445b3b05abc4a200ea393c37c9a64653f7ab568f78bc9936579c", \
    "SHA256 hash incorrect"
assert bytemultitool.get_data_hash(b"can be used here.", sha256) == \
    "25b3eb7864f90a0f49c205f762b9e6a2cfe8ec32a59225b8abd35db907f38b1a", \
    "SHA256 hash incorrect"
assert bytemultitool.get_data_hash(b"5 tests might be excessive", sha256) == \
    "7ac2c0a15431aa1937d49ef013b5422270ee99b7c9fe0761d25387f1212db0c8", \
    "SHA256 hash incorrect"
