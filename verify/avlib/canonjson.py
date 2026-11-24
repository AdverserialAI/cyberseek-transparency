"""Canonical JSON, byte-identical to attest-proxy's internal/canonjson.

Rules: object keys sorted ascending by code point, no whitespace, strings
escaped like JavaScript's JSON.stringify (only '"', '\\' and control characters
below 0x20 are escaped; everything else, including non-ASCII, is emitted raw),
integers in plain decimal, integral floats without a decimal point.
"""
from __future__ import annotations

import base64
import hashlib
import math

_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _float(f: float) -> str:
    if math.isnan(f) or math.isinf(f):
        raise ValueError("canonjson: non-finite float")
    if f == 0:
        return "0"
    if f == int(f) and abs(f) < 1e21:
        return str(int(f))
    if 1e-6 <= abs(f) < 1e21:
        return repr(f)
    mantissa, _, exp = repr(f).partition("e")
    sign = ""
    if exp[:1] in "+-":
        sign, exp = exp[0], exp[1:]
    return mantissa + "e" + sign + (exp.lstrip("0") or "0")


def dumps(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _string(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _float(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(dumps(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError("canonjson: non-string key")
        return "{" + ",".join(_string(k) + ":" + dumps(v[k]) for k in sorted(v)) + "}"
    raise TypeError("canonjson: unsupported type %s" % type(v).__name__)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def digest(v) -> str:
    """"sha256:<base64url-no-padding>" over the canonical encoding of v."""
    return "sha256:" + b64url(hashlib.sha256(dumps(v).encode("utf-8")).digest())
