#!/usr/bin/env python3
"""Validate the attestation history.

    python history/check_chain.py                      # chain + every stored file
    python history/check_chain.py --append-only-since origin/main
    python history/check_chain.py --expect-head <sha256>

Checks that every line is canonical JSON, numbered consecutively, linked to the
line before it by SHA-256, in time order, and that every stored evidence file
still has the hash recorded in its line. With --append-only-since it also
proves that the file at that git revision is a byte prefix of the current one,
i.e. history was only ever added to.

Prints the head hash: compare it with the Sigstore attestation of the same run.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "history"))

import chainlib  # noqa: E402

RELATIVE = "history/attestations.jsonl"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--no-files", action="store_true", help="skip re-hashing stored evidence files")
    ap.add_argument("--expect-head", help="fail unless the head hash equals this value")
    ap.add_argument("--append-only-since", metavar="GIT_REV", help="fail unless history only grew since this revision")
    args = ap.parse_args(argv)
    root = Path(args.root)
    path = root / RELATIVE
    try:
        count, head = chainlib.validate(path, None if args.no_files else root)
    except chainlib.ChainError as exc:
        print("FAIL: %s" % exc)
        return 1
    if args.expect_head and args.expect_head != head:
        print("FAIL: head is %s, expected %s" % (head, args.expect_head))
        return 1
    if args.append_only_since:
        shown = subprocess.run(["git", "-C", str(root), "show", "%s:%s" % (args.append_only_since, RELATIVE)],
                               capture_output=True)
        old = shown.stdout if shown.returncode == 0 else b""
        new = path.read_bytes() if path.exists() else b""
        if not chainlib.is_append_only(old, new):
            print("FAIL: history was rewritten since %s (the old file is not a prefix of the new one)" % args.append_only_since)
            return 1
    print("OK: %d entries, head %s" % (count, head))
    return 0


if __name__ == "__main__":
    sys.exit(main())
