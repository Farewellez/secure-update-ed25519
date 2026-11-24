"""CLI: python -m secure_update [keygen|publish|check|demo]."""
import argparse
import sys
from pathlib import Path

from .client import UpdateClient, UpdateRejected
from .crypto import create_key_pair
from .repository import publish_release


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m secure_update")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("keygen", help="Generate Ed25519 keys locally (private key is NOT on API server)")
    a.add_argument("--private", type=Path, default=Path("work/keys/developer-private.pem"))
    a.add_argument("--public", type=Path, default=Path("work/keys/developer-public.pem"))
    a = sub.add_parser("publish", help="Publish signed immutable release to repository")
    a.add_argument("--file", type=Path, required=True)
    a.add_argument("--version", type=int, required=True)
    a.add_argument("--private", type=Path, default=Path("work/keys/developer-private.pem"))
    a.add_argument("--repo", type=Path, default=Path("work/releases"))
    a.add_argument("--valid-days", type=int, default=30)
    a = sub.add_parser("check", help="Fetch, verify and stage a release")
    a.add_argument("--url", default="http://127.0.0.1:8000")
    a.add_argument("--public", type=Path, default=Path("work/keys/developer-public.pem"))
    a.add_argument("--state", type=Path, default=Path("work/client-state.json"))
    a.add_argument("--staging", type=Path, default=Path("work/staging"))
    sub.add_parser("demo", help="Run offline attacker simulations (no server process needed)")
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            create_key_pair(args.private, args.public)
            print(f"[OK] Private: {args.private} (KEEP SECRET); public: {args.public}")
        elif args.command == "publish":
            doc = publish_release(args.repo, args.file, args.version, args.private, args.valid_days)
            print(f"[OK] Published version {doc['signed']['version']} | SHA-256: {doc['signed']['sha256']}")
        elif args.command == "check":
            updater = UpdateClient(args.url, args.public, args.state, args.staging)
            try:
                staged = updater.run()
                print(f"[ACCEPT] Update verified and staged: {staged}")
            finally:
                updater.close()
        elif args.command == "demo":
            from .demo import main as demo_main
            demo_main()
    except UpdateRejected as exc:
        print(f"[REJECT] {exc}", file=sys.stderr)
        return 2
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
