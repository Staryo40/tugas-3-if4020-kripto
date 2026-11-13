from ..core.artifact import artifact_name
from ..crypto import keys, signature
from . import bundle, manifest
from .files import read_bytes, snapshot, write_bundle

def sign_release(file, package: str, version: str, key, out, *, force: bool = False) -> None:
    private, profile = keys.load_private_pem(read_bytes(key))
    size, digest, _ = snapshot(file)
    message = manifest.build(package, version, profile, keys.keyid(private.public_key()),
                             artifact_name(file), size, digest)
    signed = signature.sign(profile, private, message)
    write_bundle(out, bundle.serialize(message, signed), force=force, protected=(file, key))
