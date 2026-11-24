"""Credential tripwire: the rules behind tools/check_no_secrets.py.

It lives in the verifier package because `compose.keys_in_enclave` uses it too:
a release only passes that check when the published compose contains no literal
that looks like a credential. See tools/check_no_secrets.py for the rules in
prose. Findings never contain the offending value, only where it is and how
long.
"""
from __future__ import annotations

import json
import re

TOKEN_FORMATS = [
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("nvidia-api-key", re.compile(r"\bnvapi-[A-Za-z0-9_\-]{20,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("sk-api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("cloudflare-token", re.compile(r"\bcf(?:ut|at|k)_[A-Za-z0-9_\-]{30,}")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("private-jwk-member", re.compile(r"\"d\"\s*:\s*\"[A-Za-z0-9_\-]{20,}\"")),
    ("url-credentials", re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@$<{]+:[^/\s:@$<{]+@")),
    ("bearer-literal", re.compile(r"[Bb]earer\s+(?!\$|<|\{)[A-Za-z0-9._~+/\-]{16,}=*")),
]
JWT = ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"))

SENSITIVE_PART = {"KEY", "SEED", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PAT", "CREDENTIAL",
                  "CREDENTIALS", "PRIVATE", "BEARER", "IDENTITY", "APIKEY"}
EXEMPT_PART = {"PUBLIC", "PUBKEY"}
EXEMPT_SUFFIX = ("_ID", "_FILE", "_PATH", "_DIR", "_URL", "_NAME", "_COUNT", "_SHA256", "_HASH", "_TTL",
                 "_PROVIDER", "_ENABLED", "_REQUIRED", "_WRITABLE", "_TYPE")
ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_$\{])([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*(?::(?!=|//)|=(?!=))\s*"
    r"(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\$?\$\{[^}]*\}(?![^\s,;#\"'])|\$\([^)]*\)(?![^\s,;#\"'])|[^\s,;#\"']+)")
# "$$" is docker compose's escape for a literal "$" handed to the container shell.
REFERENCE = re.compile(
    r"^\$?(?:\$\{[A-Za-z_][A-Za-z0-9_]*(?::?[?][^}]*|:?-)?\}|\$[A-Za-z_][A-Za-z0-9_]*|\$\(.*\)?|`.*`?|\$[0-9@*#?])$")
PLACEHOLDER = re.compile(r"^(?:<[^<>]*>?|PLACEHOLDER\w*|REPLACE_ME\w*|CHANGEME|REDACTED|\*+|x+|\.\.\.)$", re.I)
# Names that end like this say where something is, not what it is. They are
# exempt only while the value really is a location (see is_location).
LOCATION_SUFFIX = ("_FILE", "_PATH", "_DIR")
# Command-line flags such as `--api-key VALUE`: a flag is sensitive when one of
# its dash-separated words is in SENSITIVE_PART (so --max-total-tokens is not).
FLAG = re.compile(r"(?<![A-Za-z0-9_-])--?([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)(?:[ \t]+|=)"
                  r"(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s\"',;#]+)")
BARE_FLAG = re.compile(r"^\s*-\s+[\"']?--?([A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*)[\"']?\s*$")
LIST_ITEM = re.compile(r"^\s*-\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\S.*?)\s*$")
# The "source" profile, for program text and documentation: there `key = ...`
# is ordinary code, so only a long, unbroken base64 or hex literal counts.
LONG_LITERAL = re.compile(r"[A-Za-z0-9+/_=-]{40,}")
HARMLESS = {"", "true", "false", "null", "none", "nil", "yes", "no", "on", "off", "|", ">", "|-", ">-", "[]", "{}", "[", "{"}


def is_sensitive_name(name: str) -> bool:
    upper = name.upper()
    parts = set(re.split(r"_+", upper))
    if parts & EXEMPT_PART or upper.endswith(EXEMPT_SUFFIX):
        return False
    return bool(parts & SENSITIVE_PART)


def is_location(value: str) -> bool:
    """True for a filesystem path, a reference or a placeholder: what a *_FILE, *_PATH or *_DIR should hold."""
    v = value.strip().strip("\"'").strip()
    return v.startswith(("/", "./", "../", "~/")) or is_allowed_value(value)


def is_sensitive_flag(flag: str) -> bool:
    parts = flag.upper().split("-")
    if parts[-1] in ("FILE", "PATH", "DIR", "ID", "NAME", "URL"):
        return False
    return bool(set(parts) & SENSITIVE_PART)


def is_allowed_value(value: str) -> bool:
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    if v.lower() in HARMLESS or REFERENCE.match(v) or PLACEHOLDER.match(v):
        return True
    v = v.rstrip(")}],;")  # code such as f(flag=True)}) embedded in a compose command
    if v.lower() in HARMLESS:
        return True
    return bool(re.fullmatch(r"[0-9.]+[smhd]?", v))


def scan_text(text: str, profile: str = "strict") -> list[tuple[int, str, str]]:
    """Return [(line number, rule, redacted description)]."""
    findings = []
    rules = TOKEN_FORMATS + ([JWT] if profile.startswith("strict") or profile == "source" else [])
    pending_flag = None
    for number, line in enumerate(text.splitlines(), 1):
        for rule, pattern in rules:
            for m in pattern.finditer(line):
                findings.append((number, rule, "%d characters" % len(m.group(0))))
        if profile == "source":
            for m in ASSIGNMENT.finditer(line):
                value = m.group(2).strip("\"'")
                if is_sensitive_name(m.group(1)) and LONG_LITERAL.fullmatch(value):
                    findings.append((number, "assignment", "%s is assigned a %d-character base64 or hex literal"
                                     % (m.group(1), len(value))))
        if profile != "strict":
            continue
        for m in ASSIGNMENT.finditer(line):
            name, value = m.group(1), m.group(2)
            if is_sensitive_name(name) and not is_allowed_value(value):
                findings.append((number, "assignment", "%s is assigned a %d-character literal" % (name, len(value.strip("\"'")))))
            elif (name.upper().endswith(LOCATION_SUFFIX) and set(re.split(r"_+", name.upper())) & SENSITIVE_PART
                  and not is_location(value)):
                findings.append((number, "assignment", "%s should hold a path but is assigned a %d-character literal"
                                 % (name, len(value.strip("\"'")))))
        # --api-key VALUE on one line, or as two consecutive list items.
        if pending_flag:
            item = LIST_ITEM.match(line)
            if item and not is_allowed_value(item.group(1)):
                findings.append((number, "flag-literal", "--%s is followed by a %d-character literal"
                                 % (pending_flag, len(item.group(1).strip("\"'")))))
        bare = BARE_FLAG.match(line)
        pending_flag = bare.group(1) if bare and is_sensitive_flag(bare.group(1)) else None
        for m in FLAG.finditer(line):
            if is_sensitive_flag(m.group(1)) and not is_allowed_value(m.group(2)):
                findings.append((number, "flag-literal", "--%s is given a %d-character literal"
                                 % (m.group(1), len(m.group(2).strip("\"'")))))
    return findings


def _strings(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _strings(v, "%s.%s" % (path, k) if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _strings(v, "%s[%d]" % (path, i))
    elif isinstance(node, str):
        yield path, node


def scan_document(label: str, text: str, is_json: bool, profile: str = "strict") -> list[str]:
    """Scan one document held in memory. `label` is only used to name findings."""
    if not is_json:
        return ["%s:%d: %s: %s" % (label, n, rule, what) for n, rule, what in scan_text(text, profile)]
    # JSON: token formats on the raw text, then every decoded string. Multi-line
    # strings (an embedded compose file or script) get the full line-based scan.
    relaxed = profile if profile in ("evidence", "source") else "strict-no-assignment"
    out = ["%s:%d: %s: %s" % (label, n, rule, what) for n, rule, what in scan_text(text, relaxed)]
    try:
        doc = json.loads(text)
    except ValueError:
        return out + ["%s: invalid-json: file does not parse" % label]
    for where, value in _strings(doc):
        if "\n" in value:
            out += ["%s:%s:%d: %s: %s" % (label, where, n, rule, what) for n, rule, what in scan_text(value, profile)]
        name = "" if where.endswith("]") else re.split(r"[.\[]", where)[-1]
        if profile == "strict" and name and is_sensitive_name(name) and not is_allowed_value(value):
            out.append("%s:%s: assignment: %s holds a %d-character literal" % (label, where, name, len(value)))
        if profile == "source" and name and is_sensitive_name(name) and LONG_LITERAL.fullmatch(value):
            out.append("%s:%s: assignment: %s holds a %d-character base64 or hex literal" % (label, where, name, len(value)))
    return sorted(set(out))
