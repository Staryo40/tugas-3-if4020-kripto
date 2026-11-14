import pytest

from tacstmu import cli
from tacstmu.core.constants import PROFILES
from tacstmu.crypto import keys
from tacstmu.release import trust


def add_args(public, store, package="app"):
    return ["trust", "add", "--key", str(public), "--package", package, "--store", str(store)]


@pytest.mark.parametrize("profile", PROFILES)
def test_create_extend_list_and_remove(tmp_path, signing_keys, capsys, profile):
    public = signing_keys[profile].public_key()
    fingerprint = keys.keyid(public)
    key = tmp_path / "publisher.pub.pem"
    key.write_bytes(keys.public_pem(public))
    store = tmp_path / "trust.json"
    assert cli.main(add_args(key, store)) == 0
    assert capsys.readouterr().out == f"{fingerprint}\t{profile}\tapp\n"
    assert trust.load_trust_store(store).find(fingerprint).packages == frozenset({"app"})

    assert cli.main(add_args(key, store, "app-sbom")) == 0
    capsys.readouterr()
    before = store.read_bytes(), store.stat().st_mtime_ns
    assert cli.main(add_args(key, store, "app-sbom")) == 0
    capsys.readouterr()
    assert (store.read_bytes(), store.stat().st_mtime_ns) == before
    assert cli.main(["trust", "list", "--store", str(store)]) == 0
    assert capsys.readouterr().out == f"{fingerprint}\t{profile}\tapp,app-sbom\n"

    assert cli.main(["trust", "remove", "--keyid", fingerprint, "--store", str(store)]) == 0
    assert trust.load_trust_store(store).entries == {}
    assert cli.main(["trust", "list", "--store", str(store)]) == 0
    assert capsys.readouterr().out == ""
    before = store.read_bytes()
    assert cli.main(["trust", "remove", "--keyid", fingerprint, "--store", str(store)]) == 2
    assert store.read_bytes() == before
    assert "not in the trust store" in capsys.readouterr().err


def test_add_preserves_other_keys_and_remove_only_deletes_requested_entry(tmp_path, signing_keys):
    store = tmp_path / "trust.json"
    fingerprints = []
    for profile in PROFILES:
        public = signing_keys[profile].public_key()
        key = tmp_path / f"{profile}.pub.pem"
        key.write_bytes(keys.public_pem(public))
        fingerprints.append(trust.add_trusted_key(store, key, "app").keyid)
    trust.remove_trusted_key(store, fingerprints[0])
    assert set(trust.load_trust_store(store).entries) == set(fingerprints[1:])


@pytest.mark.parametrize("operation", ["add", "list", "remove"])
def test_malformed_store_is_rejected_without_changes(make_release, capsys, operation):
    case = make_release()
    key = case.key.with_name("publisher.pub.pem")
    key.write_bytes(keys.public_pem(case.public))
    case.trust.write_bytes(b'{"schema":"minisign-trust/v1","keys":[],"keys":[]}')
    before = case.trust.read_bytes()
    argv = {"add": add_args(key, case.trust),
            "list": ["trust", "list", "--store", str(case.trust)],
            "remove": ["trust", "remove", "--keyid", case.keyid, "--store", str(case.trust)]}
    assert cli.main(argv[operation]) == 2
    assert case.trust.read_bytes() == before
    captured = capsys.readouterr()
    assert captured.out == "" and "duplicate" in captured.err


@pytest.mark.parametrize("fault", ["package", "key", "parent", "alias"])
def test_invalid_add_does_not_write(tmp_path, signing_keys, capsys, fault):
    key = tmp_path / "publisher.pub.pem"
    key.write_bytes(keys.public_pem(signing_keys["ed25519"].public_key()))
    original = key.read_bytes()
    store = tmp_path / "trust.json"
    package = "app"
    if fault == "package":
        package = "*"
    elif fault == "key":
        key.write_bytes(b"bad key")
    elif fault == "parent":
        store = tmp_path / "missing" / "trust.json"
    else:
        store = key
    assert cli.main(add_args(key, store, package)) == 2
    assert capsys.readouterr().out == ""
    if fault == "alias":
        assert key.read_bytes() == original
    else:
        assert not store.exists()


@pytest.mark.parametrize("operation", ["list", "remove"])
def test_missing_store_is_an_error(tmp_path, operation):
    store = tmp_path / "missing.json"
    argv = ["trust", operation, "--store", str(store)]
    if operation == "remove":
        argv += ["--keyid", "a" * 64]
    assert cli.main(argv) == 2
    assert not store.exists()


@pytest.mark.parametrize("failure", ["fsync", "replace"])
def test_failed_save_preserves_store_and_cleans_temporary_file(make_release, monkeypatch, failure):
    case = make_release()
    before = case.trust.read_bytes()
    files_before = set(case.trust.parent.iterdir())
    def fail(*args):
        raise OSError("simulated storage failure")
    monkeypatch.setattr(trust.os, failure, fail)
    assert cli.main(["trust", "remove", "--keyid", case.keyid, "--store", str(case.trust)]) == 2
    assert case.trust.read_bytes() == before
    assert set(case.trust.parent.iterdir()) == files_before


@pytest.mark.parametrize("condition", ["removed", "empty", "other-package"])
def test_U06_U07_untrusted_keys_are_rejected(make_release, condition):
    case = make_release()
    if condition == "removed":
        assert cli.main(["trust", "remove", "--keyid", case.keyid, "--store", str(case.trust)]) == 0
    else:
        trust.save_trust_store(case.trust, trust.TrustStore({}))
        if condition == "other-package":
            key = case.key.with_name("publisher.pub.pem")
            key.write_bytes(keys.public_pem(case.public))
            assert cli.main(add_args(key, case.trust, "other-app")) == 0
    assert case.verify()["status"] == "KEY_NOT_TRUSTED"


@pytest.mark.parametrize("profile", PROFILES)
def test_trust_add_authorizes_real_sign_and_verify(make_release, profile):
    case = make_release(profile)
    trust.remove_trusted_key(case.trust, case.keyid)
    assert case.verify()["valid"] is False
    key = case.key.with_name("publisher.pub.pem")
    key.write_bytes(keys.public_pem(case.public))
    assert cli.main(add_args(key, case.trust, case.package)) == 0
    assert case.verify()["valid"] is True
