#!/usr/bin/env python3
"""Fail if a file looks like it contains a credential.

    python tools/check_no_secrets.py deployments/            # strict (default)
    python tools/check_no_secrets.py --profile evidence history/evidence/
    python tools/check_no_secrets.py --profile source .       # the whole repository

It is a tripwire that runs in CI before anything is committed, not a proof of
absence: a human still reviews every change under deployments/.

Rules
  token-format   well-known credential shapes (Hugging Face, NVIDIA, GitHub,
                 AWS, Slack, sk-..., Cloudflare), PEM private keys, private
                 JWK members, credentials inside URLs, literal Bearer headers.
  assignment     a variable whose name contains KEY, SEED, TOKEN, SECRET,
                 PASSWORD, PASSWD, PAT, CREDENTIAL, PRIVATE, BEARER or IDENTITY
                 is assigned a literal value. Allowed values: empty, a pure
                 reference (${VAR}, $VAR, $$VAR, ${VAR:?message}, $(command)), a
                 <placeholder>, or a boolean/number. Names that describe public
                 material (PUBLIC, PUBKEY, *_ID, *_URL, *_NAME, *_COUNT,
                 *_SHA256, *_HASH) are exempt. Names that describe a location
                 (*_FILE, *_PATH, *_DIR) are exempt only while the value is a
                 path: UPSTREAM_BEARER_TOKEN_FILE: /run/handoff/upstream-token
                 is fine, the same name holding anything else is a finding.
  flag-literal   a command-line flag whose name has one of those words
                 (--api-key, --hf-token ...) is followed by a literal, on the
                 same line or as the next list item. `--api-key "$$KEY"` is a
                 reference and is fine.
  jwt            a compact JWT (strict profile only; evidence legitimately
                 contains signed NVIDIA tokens and receipts).

Profiles
  strict     everything above. For deployment files: configuration, where any
             literal next to a sensitive name is suspect.
  evidence   token-format only, binary files tolerated. For recorded
             attestation evidence, which is public by construction.
  source     token-format, jwt, and `assignment` narrowed to a sensitive name
             holding 40 or more unbroken base64 or hex characters. For program
             text, tests, workflows and documentation, where `key = load(...)`
             is ordinary code. Directories named .git, __pycache__,
             .pytest_cache, .venv and venv are skipped. Files under
             history/evidence/ are recorded attestation evidence, not program
             text: a scan of the whole repository applies the evidence
             profile to them (they are full of signed NVIDIA tokens, Intel
             signatures and public key configurations).

JSON files are parsed and every string inside them is scanned as text too, so
a docker compose embedded in app-compose.json is covered.

Findings never print the offending value, only where it is and how long.
Exit status: 0 clean, 1 findings, 2 usage error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verify"))

from avlib.secretscan import (  # noqa: E402,F401  (re-exported for the other tools and the tests)
    is_allowed_value, is_sensitive_name, scan_document, scan_text)


SKIPPED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv"}


def scan_file(path: Path, profile: str = "strict") -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        if profile == "evidence":
            return []
        return ["%s: binary-file: cannot be scanned; only text files may be published here" % path]
    return scan_document(str(path), text, path.suffix == ".json", profile)


def profile_for(path: Path, profile: str) -> str:
    """The profile to apply to one file: recorded evidence is evidence, wherever the scan started."""
    parts = path.resolve().parts
    recorded = any(parts[i:i + 2] == ("history", "evidence") for i in range(len(parts) - 1))
    return "evidence" if profile == "source" and recorded else profile


def iter_files(targets):
    for target in targets:
        p = Path(target)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and not set(f.parts) & SKIPPED_DIRS:
                    yield f
        elif p.is_file():
            yield p
        else:
            raise FileNotFoundError(target)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fail if a file looks like it contains a credential.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--profile", choices=("strict", "evidence", "source"), default="strict")
    args = ap.parse_args(argv)
    try:
        files = list(iter_files(args.paths))
    except FileNotFoundError as exc:
        print("error: no such path: %s" % exc, file=sys.stderr)
        return 2
    findings = [line for f in files for line in scan_file(f, profile_for(f, args.profile))]
    for line in findings:
        print(line)
    print("%s: scanned %d files, %d findings" % ("FAIL" if findings else "OK", len(files), len(findings)))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
