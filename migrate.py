#!/usr/bin/env python3
"""Backfill account_id onto pre-accounts secrets.json and deliveries/*.json.

Usage:
  python migrate.py --data-dir ./data --username alice
  python migrate.py --data-dir ./data --username alice --verified-only
  python migrate.py --data-dir ./data --username alice --dry-run
"""

import argparse
import json
import sys
from pathlib import Path


def load(p: Path):
    return json.loads(p.read_text()) if p.exists() else []


def save(p: Path, items):
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(items, indent=2))
    tmp.replace(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--username", required=True, help="Account to attach the data to.")
    ap.add_argument(
        "--verified-only",
        action="store_true",
        help="Only attach verified deliveries. Unverified stay invisible.",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    data = Path(args.data_dir).resolve()
    accounts = load(data / "accounts.json")
    print(data)
    account = next(
        (a for a in accounts if a["username"].lower() == args.username.lower()), None
    )
    if not account:
        sys.exit(
            f"No account named '{args.username}'. Existing: "
            + ", ".join(a["username"] for a in accounts)
            or "(none)"
        )

    aid = account["id"]
    print(f"Target account: {args.username}  ({aid})")

    # --- secrets ---
    secrets = load(data / "secrets.json")
    n_sec = 0
    for s in secrets:
        if s.get("account_id") is None:
            s["account_id"] = aid
            n_sec += 1
    print(f"Secrets: {n_sec} of {len(secrets)} need attribution.")

    # --- deliveries ---
    deliv_dir = data / "deliveries"
    files = sorted(deliv_dir.glob("*.json")) if deliv_dir.exists() else []
    to_fix = []
    for f in files:
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        if d.get("account_id") is not None:
            continue
        if args.verified_only and not d.get("verified"):
            continue
        to_fix.append((f, d))
    print(f"Deliveries: {len(to_fix)} of {len(files)} need attribution.")

    if args.dry_run:
        print("Dry run — nothing written.")
        return

    save(data / "secrets.json", secrets)
    for f, d in to_fix:
        d["account_id"] = aid
        save(f, d)

    print(
        f"Done. {n_sec} secrets + {len(to_fix)} deliveries attached to '{args.username}'."
    )


if __name__ == "__main__":
    main()
