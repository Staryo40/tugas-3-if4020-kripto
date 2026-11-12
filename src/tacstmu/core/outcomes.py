EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_ERROR = 2

STATUS_OK = "OK"

class TacstmuError(Exception):
    status = "UNKNOWN_ERROR"
    exit_code = EXIT_ERROR

class InputError(TacstmuError):
    status = "INPUT_ERROR"
    exit_code = EXIT_ERROR

class FormatError(TacstmuError):
    status = "FORMAT_ERROR"
    exit_code = EXIT_REJECTED

class UnsupportedAlgorithmError(TacstmuError):
    status = "UNSUPPORTED_ALGORITHM"
    exit_code = EXIT_REJECTED

class KeyNotTrustedError(TacstmuError):
    status = "KEY_NOT_TRUSTED"
    exit_code = EXIT_REJECTED

class InvalidSignatureError(TacstmuError):
    status = "INVALID_SIGNATURE"
    exit_code = EXIT_REJECTED

class MetadataMismatchError(TacstmuError):
    status = "METADATA_MISMATCH"
    exit_code = EXIT_REJECTED

class ArtifactMismatchError(TacstmuError):
    status = "ARTIFACT_MISMATCH"
    exit_code = EXIT_REJECTED
