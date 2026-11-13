import argparse
import json
import sys

from . import DISPLAY_NAME, __version__
from .core.constants import PROFILES
from .core.outcomes import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_REJECTED,
    STATUS_OK,
    InputError,
    TacstmuError,
)
from .crypto import keys

PROG = "tacstmu"
VERIFY_FIELDS = ("valid", "status", "message", "algorithm", "keyid", "package", "version")

def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    parser = _build_parser()

    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        return _report_usage_error(argv, exc)
    except SystemExit as exc:
        # --help and --version exit through argparse
        return exc.code if isinstance(exc.code, int) else EXIT_OK

    try:
        code = args.handler(args)
    except TacstmuError as exc:
        return _report_error(args, exc)
    except Exception as exc:
        return _report_error(args, TacstmuError(f"internal error: {type(exc).__name__}: {exc}"))

    return EXIT_OK if code is None else code

def report_verify(result: dict, as_json: bool) -> int:
    ordered = {field: result[field] for field in VERIFY_FIELDS}

    if as_json:
        sys.stdout.write(json.dumps(ordered, ensure_ascii=False) + "\n")
    else:
        print(f"{ordered['status']}: {ordered['message']}")

    if ordered["status"] == STATUS_OK and ordered["valid"] is True:
        return EXIT_OK
    if ordered["status"] == InputError.status:
        return EXIT_ERROR
    return EXIT_REJECTED


# Command handlers
def cmd_keygen(args: argparse.Namespace) -> int | None:
    key = keys.generate(args.algorithm)
    private_path, public_path = keys.write_keypair(args.out, key, force=args.force)

    print(f"wrote {private_path} and {public_path}", file=sys.stderr)
    print(keys.keyid(key.public_key()))

def cmd_sign(args: argparse.Namespace) -> int | None:
    from .release.signing import sign_release
    sign_release(args.file, args.package, args.version, args.key, args.out, force=args.force)
    print(f"wrote {args.out}", file=sys.stderr)

def cmd_verify(args: argparse.Namespace) -> int | None:
    from .release.verification import verify_release
    result = verify_release(args.file, args.bundle, args.trust_store, args.package, args.version)
    return report_verify(result, args.json)


def cmd_verify_release(args: argparse.Namespace) -> int:
    from .release.sbom import verify_release_with_sbom
    result = verify_release_with_sbom(
        args.file, args.bundle, args.sbom, args.sbom_bundle, args.trust_store,
        args.package, args.version, args.sbom_package, args.sbom_version,
    )
    return report_sbom(result, args.json)


def report_sbom(result: dict, as_json: bool) -> int:
    if as_json:
        sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    else:
        print(f"{result['status']} ({result['stage']}): {result['message']}")
    if result["valid"] is True and result["status"] == STATUS_OK:
        return EXIT_OK
    return EXIT_ERROR if result["status"] == InputError.status else EXIT_REJECTED

def cmd_trust_add(args: argparse.Namespace) -> int | None:
    # TODO: add args.key for args.package to args.store, print keyid, algorithm and packages
    pass

def cmd_trust_list(args: argparse.Namespace) -> int | None:
    # TODO: print keyid, algorithm and packages of every entry in args.store
    pass

def cmd_trust_remove(args: argparse.Namespace) -> int | None:
    # TODO: remove args.keyid from args.store, InputError if it is not there
    pass


# Argument parsing
class _UsageError(Exception):
    def __init__(self, message: str, usage: str):
        super().__init__(message)
        self.usage = usage

class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        raise _UsageError(message, self.format_usage())

def _build_parser() -> _Parser:
    parser = _Parser(prog=PROG, description=DISPLAY_NAME)
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    keygen = commands.add_parser("keygen", help="generate a key pair")
    keygen.add_argument("--algorithm", required=True, choices=PROFILES, help="algorithm profile")
    keygen.add_argument("--out", required=True, metavar="PREFIX", help="writes PREFIX.key.pem and PREFIX.pub.pem")
    keygen.add_argument("--force", action="store_true", help="overwrite existing key files")
    keygen.set_defaults(handler=cmd_keygen)

    sign = commands.add_parser("sign", help="sign an artifact into a bundle")
    sign.add_argument("--file", required=True, metavar="PATH", help="artifact to sign")
    sign.add_argument("--package", required=True, metavar="NAME", help="package name")
    sign.add_argument("--version", required=True, metavar="VERSION", help="release version")
    sign.add_argument("--key", required=True, metavar="PRIVATE_PEM", help="private key file")
    sign.add_argument("--out", required=True, metavar="BUNDLE", help="bundle file to write")
    sign.add_argument("--force", action="store_true", help="overwrite an existing bundle")
    sign.set_defaults(handler=cmd_sign)

    verify = commands.add_parser("verify", help="verify an artifact against a bundle")
    verify.add_argument("--file", required=True, metavar="PATH", help="artifact to check")
    verify.add_argument("--bundle", required=True, metavar="BUNDLE", help="bundle file")
    verify.add_argument("--trust-store", required=True, metavar="TRUST_JSON", help="trust store file")
    verify.add_argument("--package", required=True, metavar="NAME", help="expected package name")
    verify.add_argument("--version", required=True, metavar="VERSION", help="expected release version")
    verify.add_argument("--json", action="store_true", help="print the result as JSON")
    verify.set_defaults(handler=cmd_verify)

    combined = commands.add_parser("verify-release", help="verify release and signed SBOM, then their SHA-256 binding")
    combined.add_argument("--file", required=True, metavar="PATH", help="release artifact")
    combined.add_argument("--bundle", required=True, metavar="BUNDLE", help="release bundle")
    combined.add_argument("--sbom", required=True, metavar="SBOM_JSON", help="SBOM artifact")
    combined.add_argument("--sbom-bundle", required=True, metavar="BUNDLE", help="SBOM bundle")
    combined.add_argument("--trust-store", required=True, metavar="TRUST_JSON")
    combined.add_argument("--package", required=True, help="expected release package")
    combined.add_argument("--version", required=True, help="expected release version")
    combined.add_argument("--sbom-package", required=True, help="expected SBOM package")
    combined.add_argument("--sbom-version", required=True, help="expected SBOM version")
    combined.add_argument("--json", action="store_true")
    combined.set_defaults(handler=cmd_verify_release)

    trust = commands.add_parser("trust", help="manage trusted public keys")
    trust_commands = trust.add_subparsers(dest="trust_command", required=True, metavar="<trust command>")

    trust_add = trust_commands.add_parser("add", help="trust a public key for a package")
    trust_add.add_argument("--key", required=True, metavar="PUBLIC_PEM", help="public key file")
    trust_add.add_argument("--package", required=True, metavar="NAME", help="package the key may sign")
    trust_add.add_argument("--store", required=True, metavar="TRUST_JSON", help="trust store file")
    trust_add.set_defaults(handler=cmd_trust_add)

    trust_list = trust_commands.add_parser("list", help="list trusted keys")
    trust_list.add_argument("--store", required=True, metavar="TRUST_JSON", help="trust store file")
    trust_list.set_defaults(handler=cmd_trust_list)

    trust_remove = trust_commands.add_parser("remove", help="remove a trusted key")
    trust_remove.add_argument("--keyid", required=True, metavar="KEYID", help="fingerprint to remove")
    trust_remove.add_argument("--store", required=True, metavar="TRUST_JSON", help="trust store file")
    trust_remove.set_defaults(handler=cmd_trust_remove)

    return parser


# Error reporting
def _report_usage_error(argv: list[str], exc: _UsageError) -> int:
    sys.stderr.write(exc.usage)
    print(f"{PROG}: error: {exc}", file=sys.stderr)

    if argv[:1] == ["verify"] and "--json" in argv:
        report_verify(_failed_result(InputError.status, f"usage error: {exc}"), as_json=True)
    elif argv[:1] == ["verify-release"] and "--json" in argv:
        report_sbom(_failed_sbom_result(f"usage error: {exc}"), as_json=True)

    return EXIT_ERROR

def _report_error(args: argparse.Namespace, exc: TacstmuError) -> int:
    print(f"{PROG}: error: {exc}", file=sys.stderr)

    if args.command == "verify-release":
        return report_sbom(_failed_sbom_result(str(exc)), args.json)

    if args.command == "verify":
        # an unclassified error is reported as an input/environment failure
        status = exc.status if type(exc) is not TacstmuError else InputError.status
        return report_verify(_failed_result(status, str(exc)), args.json)

    return EXIT_ERROR

def _failed_result(status: str, message: str) -> dict:
    return {
        "valid": False,
        "status": status,
        "message": message,
        "algorithm": None,
        "keyid": None,
        "package": None,
        "version": None,
    }

def _failed_sbom_result(message: str) -> dict:
    return {"valid": False, "status": InputError.status, "message": message,
            "stage": "input", "release": None, "sbom": None, "binding_valid": False}
