import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from secure_update.client import UpdateClient, UpdateRejected, load_version
from secure_update.crypto import create_key_pair, read_private_key, sign_object
from secure_update.repository import publish_release


def client(sandbox, http=None):
    return UpdateClient(
        "http://testserver", sandbox["public"], sandbox["tmp"] / "state.json",
        sandbox["tmp"] / "staging", http or sandbox["make_http"](),
    )


def reason(exc, want):
    assert exc.value.reason == want


def test_api(sandbox):
    api = sandbox["api"]
    assert api.get("/health").json() == {"status": "ok", "releases": 2}
    assert api.get("/updates/latest").json()["signed"]["version"] == 2
    assert api.get("/updates/1").json()["signed"]["version"] == 1
    assert api.get("/packages/2").content == b"legitimate NEW version"
    assert api.get("/updates/0").status_code == 404
    assert api.get("/packages/99").status_code == 404
    assert api.get("/docs").status_code == 200


def test_happy_path(sandbox):
    updater = client(sandbox)
    destination = updater.run()
    assert destination.read_bytes() == b"legitimate NEW version"
    assert load_version(sandbox["tmp"] / "state.json") == 2


def test_modified_package_rejected(sandbox):
    (sandbox["repo"] / "2" / "package.bin").write_bytes(b"legitimate NEW versioN")
    updater = client(sandbox)
    with pytest.raises(UpdateRejected) as exc:
        updater.run()
    reason(exc, "sha256_mismatch")
    assert not (sandbox["tmp"] / "state.json").exists()


def test_package_size_rejected(sandbox):
    (sandbox["repo"] / "2" / "package.bin").write_bytes(b"much longer than original package text")
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox).run()
    reason(exc, "wrong_size")


def test_manifest_forgery_rejected(sandbox):
    path = sandbox["repo"] / "2" / "manifest.json"
    doc = json.loads(path.read_text())
    malicious = b"attacker-malware-payload"
    (sandbox["repo"] / "2" / "package.bin").write_bytes(malicious)
    doc["signed"]["sha256"] = hashlib.sha256(malicious).hexdigest()
    doc["signed"]["size"] = len(malicious)
    path.write_text(json.dumps(doc))
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox).run()
    reason(exc, "signature_invalid")


def test_signature_tampering_rejected(sandbox):
    path = sandbox["repo"] / "2" / "manifest.json"
    doc = json.loads(path.read_text())
    doc["signature"] = "A" * 88
    path.write_text(json.dumps(doc))
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox).run()
    reason(exc, "signature_invalid")


def test_replay_same_version_rejected(sandbox):
    updater = client(sandbox)
    updater.run()
    with pytest.raises(UpdateRejected) as exc:
        updater.run()
    reason(exc, "rollback_or_replay")


def test_rollback_with_valid_signature_rejected(sandbox):
    (sandbox["tmp"] / "state.json").write_text('{"max_version":2,"sha256":"ignored"}')
    def old_latest(path, request):
        if path == "/updates/latest":
            resp = sandbox["api"].get("/updates/1")
            return httpx.Response(200, content=resp.content)
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox, sandbox["make_http"](old_latest)).run()
    reason(exc, "rollback_or_replay")


def test_invalid_new_public_key_is_not_trusted(sandbox):
    attacker_private = sandbox["tmp"] / "attacker-private.pem"
    attacker_public = sandbox["tmp"] / "attacker-public.pem"
    create_key_pair(attacker_private, attacker_public)
    attacker_repo = sandbox["tmp"] / "attacker-repo"
    artifact = sandbox["tmp"] / "attack.bin"
    artifact.write_bytes(b"malicious release")
    publish_release(attacker_repo, artifact, 4, attacker_private)
    doc = json.loads((attacker_repo / "4" / "manifest.json").read_text())
    # Server menyampaikan manifest dengan key_id attacker, tapi client tetap memakai pinned key.
    def forged(path, request):
        if path == "/updates/latest":
            return httpx.Response(200, json=doc)
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox, sandbox["make_http"](forged)).run()
    reason(exc, "untrusted_key_id")


def test_expired_signed_manifest_rejected(sandbox):
    path = sandbox["repo"] / "2" / "manifest.json"
    doc = json.loads(path.read_text())
    doc["signed"]["expires_at"] = "2020-01-01T00:00:00Z"
    doc["signature"] = sign_object(read_private_key(sandbox["private"]), doc["signed"])
    path.write_text(json.dumps(doc))
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox).run()
    reason(exc, "expired_manifest")


def test_extra_field_cannot_be_injected(sandbox):
    path = sandbox["repo"] / "2" / "manifest.json"
    doc = json.loads(path.read_text())
    doc["signed"]["install_command"] = "rm -rf /"
    path.write_text(json.dumps(doc))
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox).run()
    reason(exc, "invalid_manifest")


def test_corrupt_local_state_fails_closed(sandbox):
    (sandbox["tmp"] / "state.json").write_text('{"max_version": "0"}')
    with pytest.raises(UpdateRejected) as exc:
        client(sandbox).run()
    reason(exc, "local_state_invalid")


def test_private_key_not_part_of_server_distribution(sandbox):
    assert not list(sandbox["repo"].rglob("*.pem"))
    assert sandbox["api"].get("/keys/developer-private.pem").status_code == 404


def test_publishing_prevents_same_version(sandbox):
    with pytest.raises(FileExistsError):
        publish_release(sandbox["repo"], sandbox["repo"] / "2" / "package.bin", 2, sandbox["private"])
