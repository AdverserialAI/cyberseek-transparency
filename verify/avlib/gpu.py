"""NVIDIA GPU evidence, as far as attest-proxy exposes it.

A collector container inside the VM asks each GPU for an attestation report
and submits them to NVIDIA's Remote Attestation Service (NRAS). NRAS answers
with signed tokens (EATs): one overall token plus one per GPU. The proxy
relays that bundle as evidence.gpu_evidence.

What this module checks
  * every token is signed (ES384) by a key NVIDIA publishes at the pinned
    NRAS origin - the origin is fixed here, not taken from the bundle;
  * the overall token says the platform attested successfully, carries the
    bundle nonce, and lists the SHA-256 of every per-GPU token;
  * each per-GPU token reports measurements matched, secure boot on, debug off;
  * enough GPUs are present, and the tokens were valid when the TDX quote was
    issued.

What it cannot check (see README "What you still have to trust")
  * that these GPUs are the ones attached to this VM: the NRAS nonce is chosen
    by the collector and is not derived from the TDX quote or client nonce;
  * the GPU measurements themselves: comparing them with NVIDIA's reference
    values is done by NRAS, not here.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .canonjson import b64url_decode

NRAS_ORIGIN = "https://nras.attestation.nvidia.com"
NRAS_JWKS_URL = NRAS_ORIGIN + "/.well-known/jwks.json"


class GPUError(Exception):
    pass


class GPUKeyUnknown(GPUError):
    """The token names a signing key that is not in the supplied key set."""


def _parse(compact: str) -> dict:
    parts = compact.split(".")
    if len(parts) != 3 or not all(parts):
        raise GPUError("NVIDIA token is not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except ValueError:
        raise GPUError("NVIDIA token is malformed") from None
    return {"compact": compact, "header": header, "claims": claims,
            "input": (parts[0] + "." + parts[1]).encode(), "signature": signature}


def parse_time(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def check_structure(evidence: dict, minimum_gpus: int, max_age_s: int, at: dt.datetime) -> dict:
    """Everything that needs no network. Raises GPUError; returns a summary."""
    bundle = evidence.get("gpu_evidence")
    if not isinstance(bundle, dict) or bundle.get("verdict") != "successful":
        raise GPUError("no successful NVIDIA evidence bundle in the response")
    if evidence.get("gpu_evidence_stale") is True:
        raise GPUError("the proxy marked its GPU evidence as stale")
    raw_tokens = bundle.get("eat_jwts")
    nonce, generated = bundle.get("nonce"), bundle.get("generated_at")
    if not (isinstance(raw_tokens, list) and raw_tokens and all(isinstance(t, str) for t in raw_tokens)
            and isinstance(nonce, str) and isinstance(generated, str)):
        raise GPUError("NVIDIA evidence bundle is incomplete")
    age = (at - parse_time(generated)).total_seconds()
    if age < -60 or age > max_age_s:
        raise GPUError("GPU evidence is %ds old at verification time (limit %ds)" % (age, max_age_s))
    tokens = [_parse(t) for t in raw_tokens]
    epoch = at.timestamp()
    for t in tokens:
        c = t["claims"]
        if c.get("iss") != NRAS_ORIGIN:
            raise GPUError("token issuer is not %s" % NRAS_ORIGIN)
        if not isinstance(c.get("exp"), (int, float)) or not isinstance(c.get("iat"), (int, float)):
            raise GPUError("token lacks iat/exp")
        if c["exp"] <= epoch or c["iat"] > epoch + 60:
            raise GPUError("token is expired or not yet valid at verification time")
    overall = [t for t in tokens if t["claims"].get("sub") == "NVIDIA-PLATFORM-ATTESTATION"
               and isinstance(t["claims"].get("submods"), dict)]
    if len(overall) != 1:
        raise GPUError("expected exactly one overall NVIDIA platform token")
    overall = overall[0]
    if overall["claims"].get("x-nvidia-overall-att-result") is not True:
        raise GPUError("NVIDIA did not attest the overall GPU platform")
    if overall["claims"].get("eat_nonce") != nonce:
        raise GPUError("overall token nonce does not match the bundle nonce")
    expected = set()
    for claim in overall["claims"]["submods"].values():
        if not (isinstance(claim, list) and len(claim) == 2 and claim[0] == "DIGEST"
                and isinstance(claim[1], list) and claim[1][0] == "SHA-256"):
            raise GPUError("unsupported submodule digest format")
        expected.add(claim[1][1].lower())
    detached = {hashlib.sha256(t["compact"].encode()).hexdigest(): t for t in tokens if t is not overall}
    if not expected <= set(detached):
        raise GPUError("a per-GPU token listed by the overall token is missing")
    if len(expected) < minimum_gpus:
        raise GPUError("only %d GPUs attested, policy requires %d" % (len(expected), minimum_gpus))
    models = []
    for digest in sorted(expected):
        c = detached[digest]["claims"]
        if c.get("eat_nonce") != nonce:
            raise GPUError("per-GPU token nonce does not match the bundle nonce")
        if c.get("measres") != "success" or c.get("secboot") is not True or c.get("dbgstat") != "disabled":
            raise GPUError("a GPU reports measres/secboot/dbgstat outside the accepted values")
        models.append(c.get("hwmodel"))
    return {"gpu_count": len(expected), "hwmodels": sorted(set(str(m) for m in models)),
            "generated_at": generated, "nonce_source": bundle.get("nonce_source"),
            "tokens": [t for t in tokens if t is overall or hashlib.sha256(t["compact"].encode()).hexdigest() in expected]}


def check_signatures(tokens: list, jwks: dict) -> int:
    """Verify each token's ES384 signature against NVIDIA's published keys."""
    keys = {k["kid"]: k for k in jwks.get("keys", []) if k.get("kty") == "EC" and k.get("crv") == "P-384" and k.get("kid")}
    if not keys:
        raise GPUError("NVIDIA JWKS has no P-384 keys")
    for t in tokens:
        kid = t["header"].get("kid")
        if t["header"].get("alg") != "ES384":
            raise GPUError("token is not an ES384 JWS")
        if kid not in keys:
            raise GPUKeyUnknown("token signing key id is not in the supplied NVIDIA key set")
        jwk = keys[kid]
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64url_decode(jwk["x"]), "big"),
                                            int.from_bytes(b64url_decode(jwk["y"]), "big"), ec.SECP384R1()).public_key()
        sig = t["signature"]
        if len(sig) != 96:
            raise GPUError("token signature has the wrong length")
        der = encode_dss_signature(int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big"))
        try:
            pub.verify(der, t["input"], ec.ECDSA(hashes.SHA384()))
        except InvalidSignature:
            raise GPUError("NVIDIA token signature is invalid") from None
    return len(tokens)
