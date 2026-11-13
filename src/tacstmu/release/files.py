import hashlib
import os
from pathlib import Path
import tempfile

from ..core.outcomes import InputError

def read_bytes(path, limit: int | None = None) -> bytes:
    try:
        with open(path, "rb") as stream:
            return stream.read() if limit is None else stream.read(limit + 1)
    except OSError as exc:
        raise InputError(f"cannot read '{path}': {exc.strerror or exc}") from None

def snapshot(path, capture: bool = False) -> tuple[int, str, bytes | None]:
    digest = hashlib.sha256()
    size = 0
    chunks = [] if capture else None
    try:
        with open(path, "rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
    except OSError as exc:
        raise InputError(f"cannot read artifact '{path}': {exc.strerror or exc}") from None
    return size, digest.hexdigest(), b"".join(chunks) if chunks is not None else None

def write_bundle(path, data: bytes, *, force: bool, protected=()) -> None:
    target = Path(path)
    temporary = None
    try:
        for source in protected:
            if target.resolve() == Path(source).resolve() or (
                target.exists() and os.path.samefile(target, source)
            ):
                raise InputError("bundle output must not overwrite an input file")
        if not force and os.path.lexists(target):
            raise InputError(f"refusing to overwrite existing bundle '{target}'")
        fd, temporary = tempfile.mkstemp(prefix=".tacstmu-", dir=target.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, target)
        elif os.name == "nt":
            os.rename(temporary, target)
        else:
            os.link(temporary, target)
    except OSError as exc:
        raise InputError(f"cannot write bundle '{target}': {exc.strerror or exc}") from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
