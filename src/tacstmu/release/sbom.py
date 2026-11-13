from ..core import jsoncheck
from ..core.constants import HEX64_RE
from ..core.outcomes import FormatError
from .verification import verify_details

SCHEMA_SBOM = "tacstmu-sbom/v1"

def parse_sbom(data: bytes) -> dict:
    obj = jsoncheck.expect_object(jsoncheck.loads(data), {
        "schema": str, "release": dict, "components": list,
    })
    if obj["schema"] != SCHEMA_SBOM:
        raise FormatError("unknown SBOM schema")
    release = jsoncheck.expect_object(obj["release"], {"sha256": str})
    if not HEX64_RE.fullmatch(release["sha256"]):
        raise FormatError("SBOM release SHA-256 must be 64 lowercase hexadecimal characters")
    for component in obj["components"]:
        item = jsoncheck.expect_object(component, {"name": str, "version": str})
        if not item["name"] or not item["version"]:
            raise FormatError("SBOM component name and version must be nonempty")
    return obj

def verify_release_with_sbom(file, bundle_path, sbom, sbom_bundle, trust_store,
                             package: str, version: str, sbom_package: str, sbom_version: str) -> dict:
    """Release first, then SBOM, then SBOM format, then binding. Never reread SBOM."""
    release_result, release = verify_details(file, bundle_path, trust_store, package, version)
    result = {"valid": False, "status": release_result["status"], "message": release_result["message"],
              "stage": "release", "release": release_result, "sbom": None, "binding_valid": False}
    if release is None:
        return result
    sbom_result, authenticated = verify_details(sbom, sbom_bundle, trust_store,
                                                sbom_package, sbom_version, capture=True)
    result.update(status=sbom_result["status"], message=sbom_result["message"],
                  stage="sbom", sbom=sbom_result)
    if authenticated is None:
        return result
    result["stage"] = "binding"
    try:
        obj = parse_sbom(authenticated.content)
    except FormatError as exc:
        result.update(status=exc.status, message=str(exc))
        return result
    if obj["release"]["sha256"] != release.sha256:
        result.update(status="SBOM_BINDING_MISMATCH", message="Signed SBOM references a different release SHA-256.")
        return result
    result.update(valid=True, status="OK", stage="complete", binding_valid=True,
                  message="Both artifacts and signatures are valid; SBOM is bound to the release SHA-256.")
    return result
