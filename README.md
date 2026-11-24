# Secure Software Update System (Ed25519) - Educational Prototype

API-only proof-of-concept untuk tugas akhir Kriptografi Modern. **Bukan updater siap produksi.** Tidak menjalankan binary; hanya mengunduh, memverifikasi, dan memindahkan paket ke `staging/`.

## Trust model dan tujuan

- **Developer / signing authority:** menandatangani canonical JSON manifest dengan private key Ed25519. Private key tidak diletakkan dalam repository update/server API.
- **Distribution API:** menyediakan manifest + paket, tetapi dianggap dapat dikompromikan attacker.
- **Client:** public key Ed25519 developer dipasang secara lokal melalui kanal tepercaya sebelum mengambil update. Client menolak signature tidak valid, paket diubah, metadata kedaluwarsa, dan versi yang tidak lebih tinggi daripada `max_version` tersimpan.
- Metadata berisi `version`, `sha256`, `size`, `key_id`, `expires_at`, `app`, `artifact`, `schema_id`, semuanya tercakup signature. Tidak ada public key yang diterima dari API secara dinamis.

## 1. Instalasi (fish shell di CachyOS/Linux)

```fish
python -m venv .venv
source .venv/bin/activate.fish
python -m pip install -e '.[dev]'
```

## 2. Generate key developer (lokal, sekali)

```fish
python -m secure_update keygen
```

Private key `work/keys/developer-private.pem` untuk lab ini disimpan tanpa passphrase dengan mode 0600. **Jangan digunakan untuk deployment produksi.** Lokasi `work/` diabaikan `.gitignore`.

## 3. Publish versi 1 dan 2

```fish
python -m secure_update publish --version 1 --file samples/v1.txt
python -m secure_update publish --version 2 --file samples/v2.txt
```

Release disimpan pada `work/releases/1/` dan `work/releases/2/`. Setiap versi hanya boleh dipublish satu kali oleh tool ini.

## 4. Jalankan FastAPI

Terminal pertama:

```fish
uvicorn secure_update.api:app --host 127.0.0.1 --port 8000
```

Buka http://127.0.0.1:8000/docs untuk Swagger UI otomatis. Endpoint:

| Endpoint | Fungsi |
|---|---|
| `GET /health` | Status API |
| `GET /updates/latest` | Manifest & signature versi tertinggi |
| `GET /updates/{version}` | Manifest & signature versi tertentu |
| `GET /packages/{version}` | Byte file release |

Terminal kedua:

```fish
source .venv/bin/activate.fish
python -m secure_update check
```

Harusnya muncul `[ACCEPT] ... work/staging/cielapp-v2.bin`. Menjalankan `check` kedua kalinya akan menghasilkan `[REJECT] rollback_or_replay` karena versi yang sama telah dicatat. Untuk demo client baru, gunakan `--state work/another-state.json --staging work/another-staging`.

## 5. Jalankan simulasi serangan & tests

```fish
python -m secure_update demo
python -m pytest -q
python -m secure_update.benchmark --trials 12
```

Simulasi menggunakan FastAPI TestClient dan in-memory HTTP transport, **tanpa proses server external**. Ia menguji update normal, package tampering, manifest forgery, dan rollback; pytest mencakup skenario tambahan. Benchmark menguji SHA-256 pada 1/10/50 MB serta sign/verify metadata kecil (bukan transfer end-to-end). Batas ukuran paket yang diterima client: 64 MiB.

## Struktur proyek

```
secure_update/
  __main__.py   CLI keygen/publish/check/demo
  crypto.py     Ed25519 sign/verify, SHA-256 fingerprint public key
  protocol.py   Pydantic schema, canonical JSON, validasi metadata
  repository.py Publish paket + manifest (offline signer)
  api.py        FastAPI server distribusi (tidak perlu private key)
  client.py     Validasi, anti-rollback, staging tanpa execute
  demo.py       Attack simulation dengan HTTP mock
samples/         File update harmless (teks)
tests/           Security tests
docs/            Proposal / bukti pengujian
```

## Batasan keamanan (wajib dijelaskan dalam laporan)

- **Belum TUF-compliant**: tidak ada root/targets/snapshot/timestamp roles, threshold signatures, rotasi kunci atau recovery kompromi signer.
- Anti-rollback hanya berlaku jika `state.json` tidak diubah penyerang dan klien pernah melihat versi lebih tinggi. Pengguna baru tetap dapat menerima release lama yang belum kedaluwarsa.
- `expires_at` mendeteksi metadata kedaluwarsa tetapi tidak menjamin klien mendapat update terbaru sebelum masa tersebut. Keamanan bergantung pada jam client.
- Jika private key developer bocor atau public key trust anchor diganti secara lokal, signature saja tidak bisa menyelamatkan sistem.
- Tidak menggunakan TLS untuk demo loopback; produksi membutuhkan HTTPS, hardening, pelindungan key dan state, serta kebijakan fail-safe.
- `save_version()` dan staging bukan transaksi yang sepenuhnya atomik terhadap kerusakan storage/power failure. Keamanan concurrency dan atomic installation di luar scope.
- **Ed25519 adalah signature, bukan encryption**. Hash SHA-256 mengikat isi file ke signed manifest, bukan menggantikan signature.
- Tidak ada eksekusi paket, instalasi otomatis, CI/CD produksi, atau update kernel/OS nyata.

## Referensi utama

- RFC 8032 (Ed25519): https://www.rfc-editor.org/rfc/rfc8032
- NIST FIPS 180-4 (SHA-256): https://csrc.nist.gov/pubs/fips/180-4/final
- The Update Framework specification: https://theupdateframework.github.io/specification/latest/
- TUF security model: https://theupdateframework.io/docs/security/
- NIST SP 800-218 (Secure Software Development Framework): https://csrc.nist.gov/pubs/sp/800/218/final
