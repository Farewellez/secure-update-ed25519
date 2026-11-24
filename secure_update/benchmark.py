"""Benchmark terkontrol lokal: SHA-256 file (1/10/50 MB) + Ed25519 sign/verify manifest."""
import argparse
import csv
import hashlib
import json
import platform
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import __version__ as cryptography_version
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import sign_object, verify_object
from .protocol import canonical_bytes


def measure(action, trials):
    samples = []
    for _ in range(trials):
        begin = time.perf_counter_ns()
        action()
        samples.append((time.perf_counter_ns() - begin) / 1_000_000)
    return round(statistics.median(samples), 5), round(min(samples), 5), round(max(samples), 5)


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("docs/benchmark_aktual.csv"))
    parser.add_argument("--trials", type=int, default=12)
    args = parser.parse_args(argv)
    if args.trials < 3:
        raise ValueError("Gunakan minimal 3 trials")
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    payload = {"app": "CielApp", "version": 2, "sha256": "a" * 64}
    signature = sign_object(priv, payload)
    records = []
    with tempfile.TemporaryDirectory() as folder:
        p = Path(folder) / "artifact.bin"
        for mb in (1, 10, 50):
            with p.open("wb") as f:
                # Deterministic non-secret bytes; total exactly MB * 1,000,000 bytes.
                for _ in range(mb):
                    f.write(b"B" * 1_000_000)
            for operation, action in [
                ("sha256_stream", lambda: sha_file(p)),
                ("ed25519_sign_manifest", lambda: sign_object(priv, payload)),
                ("ed25519_verify_manifest", lambda: verify_object(pub, payload, signature)),
            ]:
                med, lo, hi = measure(action, args.trials)
                records.append({
                    "file_size_mb": mb,
                    "operation": operation,
                    "trials": args.trials,
                    "median_ms": med,
                    "min_ms": lo,
                    "max_ms": hi,
                    "environment": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}, cryptography {cryptography_version}",
                })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    print(f"[OK] {len(records)} benchmark records written to {args.output}")
    for r in records:
        print(f"{r['file_size_mb']:2d} MB | {r['operation']:24s} | median {r['median_ms']:>9.5f} ms")
    print("NOTE: Ini hanya benchmark lokal; tidak mengukur HTTPS/download/installer atau konsumsi memori")


if __name__ == "__main__":
    main()
