"""Demonstrasi attacker vs client secara offline dengan FastAPI TestClient."""
import hashlib
import json
import tempfile
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from .api import create_app
from .client import UpdateClient, UpdateRejected
from .crypto import create_key_pair
from .repository import publish_release


def run_scenario(name: str, attack: str | None, expected: str):
    with tempfile.TemporaryDirectory() as root:
        root = Path(root)
        keys = root / "keys"
        private, public = keys / "developer.pem", keys / "developer.pub.pem"
        create_key_pair(private, public)
        repo = root / "repo"
        source1 = root / "v1.txt"
        source2 = root / "v2.txt"
        source1.write_bytes(b"CielApp 1.0 - old but correctly signed")
        source2.write_bytes(b"CielApp 2.0 - expected release")
        publish_release(repo, source1, 1, private)
        publish_release(repo, source2, 2, private)
        state = root / "client-state.json"
        if attack == "rollback":
            state.write_text('{"max_version": 2, "sha256": "already-installed"}')
        if attack == "package_tampering":
            package = repo / "2" / "package.bin"
            package.write_bytes(package.read_bytes().replace(b"release", b"releasE"))
        if attack == "manifest_forgery":
            doc_path = repo / "2" / "manifest.json"
            doc = json.loads(doc_path.read_text())
            malicious = b"attacker release pretending to be developer"
            (repo / "2" / "package.bin").write_bytes(malicious)
            doc["signed"]["sha256"] = hashlib.sha256(malicious).hexdigest()
            doc["signed"]["size"] = len(malicious)
            doc_path.write_text(json.dumps(doc))
        api = TestClient(create_app(repo))

        def handler(request):
            route = request.url.path
            if attack == "rollback" and route == "/updates/latest":
                route = "/updates/1"
            resp = api.request(request.method, route)
            return httpx.Response(resp.status_code, content=resp.content)

        http = httpx.Client(transport=httpx.MockTransport(handler))
        updater = UpdateClient("http://testserver", public, state, root / "staging", http)
        try:
            try:
                updater.run()
                observed = "accepted"
            except UpdateRejected as exc:
                observed = exc.reason
        finally:
            http.close()
        ok = observed == expected
        print(f"{'PASS' if ok else 'FAIL'} | {name:23s} | {observed}")
        return ok


def main():
    print("=== Offline Attack Simulation (real FastAPI handlers, local mock transport) ===")
    experiments = [
        ("Normal update", None, "accepted"),
        ("Package tampering", "package_tampering", "sha256_mismatch"),
        ("Manifest forgery", "manifest_forgery", "signature_invalid"),
        ("Rollback v2 -> v1", "rollback", "rollback_or_replay"),
    ]
    success = all([run_scenario(*exp) for exp in experiments])
    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
