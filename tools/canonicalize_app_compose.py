#!/usr/bin/env python3
"""Produce the publishable deployment files from a Phala Cloud API snapshot.

    python tools/canonicalize_app_compose.py cvm.json --out deployments/<release>/

`cvm.json` is the JSON the Phala Cloud API returns for the VM (it has a
"compose_file" object and a "compose_hash"), or a bare app-compose object.
The tool rebuilds the exact bytes the guest measured (the rule, and its one
difference between manifest version 2 and "3", is in verify/avlib/compose.py),
writes them as app-compose.json plus docker-compose.yml extracted from it, and
REFUSES to write anything if

  * those bytes do not hash to the snapshot's compose_hash, or
  * tools/check_no_secrets.py finds something that looks like a credential.

A compose that still contains literal secrets cannot be published: its hash
covers the secrets, so they cannot be redacted without changing the hash. Move
them to encrypted environment variables (`${NAME}` references listed in
allowed_envs), redeploy, and publish the new compose.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verify"))
sys.path.insert(0, str(ROOT / "tools"))

import check_no_secrets  # noqa: E402
from avlib import compose  # noqa: E402


def build(snapshot: dict) -> tuple[bytes, str, str | None]:
    """Return (canonical app-compose bytes, docker compose text, expected hash or None)."""
    app = snapshot.get("compose_file", snapshot)
    if not isinstance(app, dict) or "docker_compose_file" not in app:
        raise ValueError("input has no app-compose object with a docker_compose_file")
    return compose.canonical_app_compose(app), app["docker_compose_file"], snapshot.get("compose_hash")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("snapshot")
    ap.add_argument("--out", help="directory to write app-compose.json and docker-compose.yml into")
    ap.add_argument("--expect", help="compose hash to require (default: the snapshot's compose_hash)")
    args = ap.parse_args(argv)
    raw, text, expected = build(json.loads(Path(args.snapshot).read_text()))
    expected = args.expect or expected
    actual = compose.sha256_hex(raw)
    print("compose_hash  %s" % actual)
    if expected and actual != expected:
        print("error: expected compose_hash %s" % expected, file=sys.stderr)
        return 1
    findings = check_no_secrets.scan_text(text) + check_no_secrets.scan_text(json.loads(raw).get("pre_launch_script") or "")
    if findings:
        for line, rule, what in findings:
            print("secret-scan: line %d: %s: %s" % (line, rule, what), file=sys.stderr)
        print("error: refusing to write files that look like they contain %d credentials" % len(findings), file=sys.stderr)
        return 1
    try:
        declared, computed = compose.self_digest(text)
        print("COMPOSE_DIGEST %s (%s)" % (computed, "consistent" if declared == computed else "MISMATCH, declared " + declared))
    except ValueError as exc:
        print("COMPOSE_DIGEST not checked: %s" % exc)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "app-compose.json").write_bytes(raw)
        (out / "docker-compose.yml").write_text(text, encoding="utf-8", newline="")
        print("wrote %s and %s" % (out / "app-compose.json", out / "docker-compose.yml"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
