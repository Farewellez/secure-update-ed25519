"""Repository yang dapat dikendalikan attacker; tidak menyimpan private signing key."""
import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .crypto import key_id, read_private_key, sign_object
from .protocol import APP_NAME, MAX_ARTIFACT_BYTES, SCHEMA, Manifest


def publish_release(repo: Path, artifact_file: Path, version: int, private_key_file: Path, valid_days: int = 30) -> dict:
    if version < 1:
        raise ValueError("Version harus >= 1")
    if not (1 <= valid_days <= 365):
        raise ValueError("valid_days antara 1 dan 365")
    if not artifact_file.is_file():
        raise FileNotFoundError(artifact_file)
    size = artifact_file.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise ValueError("Artifact melebihi batas demo 64 MiB")
    version_path = repo / str(version)
    if version_path.exists():
        raise FileExistsError(f"Versi {version} sudah diterbitkan; immutable release")
    private = read_private_key(private_key_file)
    digest = hashlib.sha256()
    with artifact_file.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    expiry = datetime.now(timezone.utc) + timedelta(days=valid_days)
    signed = Manifest(
        schema_id=SCHEMA,
        app=APP_NAME,
        version=version,
        artifact="package.bin",
        size=size,
        sha256=digest.hexdigest(),
        key_id=key_id(private.public_key()),
        expires_at=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
    ).model_dump()
    envelope = {"signed": signed, "signature": sign_object(private, signed)}
    # Direktori versi dibuat setelah metadata valid; publikasi serial, tanpa konkurensi.
    version_path.mkdir(parents=True)
    shutil.copyfile(artifact_file, version_path / "package.bin")
    (version_path / "manifest.json").write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    return envelope


def available_versions(repo: Path) -> list[int]:
    if not repo.exists():
        return []
    return sorted(
        int(p.name) for p in repo.iterdir()
        if p.is_dir() and p.name.isdecimal() and int(p.name) > 0
        and (p / "manifest.json").is_file() and (p / "package.bin").is_file()
    )
