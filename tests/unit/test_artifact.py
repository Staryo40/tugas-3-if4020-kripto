import hashlib
import os

import pytest

from tacstmu.core.artifact import artifact_name, hash_file
from tacstmu.core.outcomes import InputError

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# hash_file: size and digest
def test_empty_file(tmp_path):
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")
    assert hash_file(path) == (0, EMPTY_SHA256)

def test_known_text(tmp_path):
    path = tmp_path / "abc.txt"
    path.write_bytes(b"abc")
    assert hash_file(path) == (3, ABC_SHA256)

def test_larger_than_one_chunk(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 17)
    path = tmp_path / "big.bin"
    path.write_bytes(data)
    assert hash_file(path) == (len(data), hashlib.sha256(data).hexdigest())

def test_accepts_str_path(tmp_path):
    path = tmp_path / "abc.txt"
    path.write_bytes(b"abc")
    assert hash_file(str(path)) == (3, ABC_SHA256)

def test_file_unchanged_after_hashing(tmp_path):
    path = tmp_path / "keep.bin"
    path.write_bytes(b"release bytes")
    before = path.stat()
    hash_file(path)
    after = path.stat()
    assert path.read_bytes() == b"release bytes"
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)


# hash_file: unreadable input
def test_missing_file(tmp_path):
    with pytest.raises(InputError, match="missing.zip"):
        hash_file(tmp_path / "missing.zip")

def test_directory(tmp_path):
    with pytest.raises(InputError):
        hash_file(tmp_path)


# artifact_name
@pytest.mark.parametrize(
    "path, expected",
    [
        ("contoh-app.zip", "contoh-app.zip"),
        ("dist/contoh-app.zip", "contoh-app.zip"),
        ("./dist/contoh-app.zip", "contoh-app.zip"),
        ("/input/contoh-app.zip", "contoh-app.zip"),
    ],
)
def test_artifact_name(path, expected):
    assert artifact_name(path) == expected
