"""The attestation history is a hash chain in a JSON-lines file.

Each line is one JSON object in canonical form (keys sorted, no whitespace,
UTF-8), terminated by "\\n". Its "prev" field is the SHA-256 of the previous
line's bytes without the newline; the first line uses 64 zeros. "seq" counts
from 0. Changing, removing or reordering any earlier line changes every later
"prev", so the hash of the last line (the "head") commits to the whole file.
The head is what the scheduled workflow gets timestamped by Sigstore.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


class ChainError(Exception):
    pass


def encode(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def read_lines(path: Path) -> list[bytes]:
    if not path.exists():
        return []
    data = path.read_bytes()
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise ChainError("history file does not end with a newline (truncated write?)")
    return data[:-1].split(b"\n")


def head(path: Path) -> tuple[int, str]:
    """(number of entries, hash of the last line or GENESIS)."""
    lines = read_lines(path)
    return len(lines), line_hash(lines[-1]) if lines else GENESIS


def append(path: Path, entry: dict) -> tuple[dict, str]:
    """Add seq/prev to entry, append it, and return (entry, its line hash)."""
    count, prev = head(path)
    entry = dict(entry, seq=count, prev=prev)
    line = encode(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(line + b"\n")
    return entry, line_hash(line)


def validate(path: Path, evidence_root: Path | None = None) -> tuple[int, str]:
    """Check the whole chain; with evidence_root also re-hash every stored file.

    Returns (entries, head hash). Raises ChainError on the first problem.
    """
    prev, last_time = GENESIS, ""
    lines = read_lines(path)
    for number, line in enumerate(lines):
        where = "line %d" % (number + 1)
        try:
            entry = json.loads(line)
        except ValueError:
            raise ChainError("%s is not valid JSON" % where) from None
        if not isinstance(entry, dict) or encode(entry) != line:
            raise ChainError("%s is not in canonical form" % where)
        if entry.get("seq") != number:
            raise ChainError("%s has seq %r, expected %d" % (where, entry.get("seq"), number))
        if entry.get("prev") != prev:
            raise ChainError("%s does not link to the line before it" % where)
        stamp = entry.get("timestamp", "")
        if not isinstance(stamp, str) or stamp < last_time:
            raise ChainError("%s has a timestamp earlier than the line before it" % where)
        last_time = stamp
        if evidence_root is not None:
            for name, ref in sorted((entry.get("files") or {}).items()):
                target = (evidence_root / ref["path"]).resolve()
                if evidence_root.resolve() not in target.parents:
                    raise ChainError("%s references a file outside the repository" % where)
                if not target.is_file():
                    raise ChainError("%s: stored file %s is missing" % (where, ref["path"]))
                if line_hash(target.read_bytes()) != ref["sha256"]:
                    raise ChainError("%s: stored file %s was modified" % (where, ref["path"]))
        prev = line_hash(line)
    return len(lines), prev


def is_append_only(old: bytes, new: bytes) -> bool:
    """True if `new` is `old` plus zero or more whole lines."""
    return new.startswith(old) and (len(new) == len(old) or new.endswith(b"\n"))
