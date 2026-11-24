"""Updater client: signature pinning -> version policy -> streaming hash -> staging."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature
from pydantic import ValidationError

from .crypto import key_id, read_public_key, verify_object
from .protocol import Envelope, MAX_METADATA_BYTES


class UpdateRejected(Exception):
    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def load_version(state_path: Path) -> int:
    if not state_path.exists():
        return 0
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        n = data["max_version"]
        if type(n) is not int or n < 0:
            raise ValueError("Bad version")
        return n
    except (ValueError, KeyError, TypeError) as exc:
        raise UpdateRejected("local_state_invalid", str(exc)) from exc


def save_version(state_path: Path, version: int, digest: str) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".state-", dir=state_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump({"max_version": version, "sha256": digest}, out, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, state_path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class UpdateClient:
    def __init__(self, base_url: str, public_key_file: Path, state_file: Path, stage_dir: Path,
                 http_client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.public_key = read_public_key(public_key_file)
        self.state_file = state_file
        self.stage_dir = stage_dir
        self.http = http_client or httpx.Client(timeout=10.0)
        self._owns_http = http_client is None

    def close(self):
        if self._owns_http:
            self.http.close()

    def run(self, now: datetime | None = None) -> Path:
        """Unduh paket saja dan simpan ke staging. Tidak mengeksekusi/install software."""
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        try:
            r = self.http.get(f"{self.base_url}/updates/latest")
            r.raise_for_status()
        except httpx.HTTPError as exc:
            raise UpdateRejected("network_error", str(exc)) from exc
        if len(r.content) > MAX_METADATA_BYTES:
            raise UpdateRejected("invalid_manifest", "Metadata too large")
        try:
            envelope = Envelope.model_validate_json(r.content)
        except ValidationError as exc:
            raise UpdateRejected("invalid_manifest", str(exc)) from exc
        signed = envelope.signed
        # Public key ditentukan secara lokal, bukan berasal dari manifest/server.
        if signed.key_id != key_id(self.public_key):
            raise UpdateRejected("untrusted_key_id")
        try:
            verify_object(self.public_key, signed.model_dump(), envelope.signature)
        except (InvalidSignature, ValueError) as exc:
            raise UpdateRejected("signature_invalid") from exc
        expiry = datetime.fromisoformat(signed.expires_at.replace("Z", "+00:00"))
        if now >= expiry:
            raise UpdateRejected("expired_manifest")
        previous_version = load_version(self.state_file)
        if signed.version <= previous_version:
            raise UpdateRejected("rollback_or_replay", f"max={previous_version}, received={signed.version}")
        self.stage_dir.mkdir(parents=True, exist_ok=True)
        temp_path: str | None = None
        try:
            fd, temp_path = tempfile.mkstemp(prefix=".download-", dir=self.stage_dir)
            size = 0
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as out:
                try:
                    with self.http.stream("GET", f"{self.base_url}/packages/{signed.version}") as response:
                        response.raise_for_status()
                        for chunk in response.iter_bytes(chunk_size=64 * 1024):
                            size += len(chunk)
                            if size > signed.size:
                                raise UpdateRejected("wrong_size", "Downloaded artifact exceeds signed size")
                            digest.update(chunk)
                            out.write(chunk)
                except httpx.HTTPError as exc:
                    raise UpdateRejected("network_error", str(exc)) from exc
                out.flush()
                os.fsync(out.fileno())
            if size != signed.size:
                raise UpdateRejected("wrong_size", f"expected={signed.size}, actual={size}")
            if digest.hexdigest() != signed.sha256:
                raise UpdateRejected("sha256_mismatch")
            final_path = self.stage_dir / f"cielapp-v{signed.version}.bin"
            os.replace(temp_path, final_path)
            temp_path = None
            # Model demo: state disimpan setelah staging; crash/FS adversary di luar cakupan.
            save_version(self.state_file, signed.version, signed.sha256)
            return final_path
        finally:
            if temp_path is not None and os.path.exists(temp_path):
                os.unlink(temp_path)
