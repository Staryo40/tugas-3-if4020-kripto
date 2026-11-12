import hashlib
import os

from .outcomes import InputError

_CHUNK_SIZE = 1024 * 1024

def hash_file(path: str | os.PathLike) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0

    try:
        with open(path, "rb") as f:
            while chunk := f.read(_CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise InputError(f"cannot read artifact '{os.fspath(path)}': {exc.strerror or exc}") from None

    return size, digest.hexdigest()

def artifact_name(path: str | os.PathLike) -> str:
    return os.path.basename(os.fspath(path))
