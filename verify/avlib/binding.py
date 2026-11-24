"""report_data constructions used by attest-proxy.

1. Fresh attestation (/attestation?nonce=..., internal/attestation/evidence.go):

       report_data[0:32]  = SHA-256( "adverserial-attestation-v2\\x00"
                                     || nonce_raw
                                     || tls_spki_der
                                     || receipt_spki_der
                                     || ehbp_receiver_pubkey )
       report_data[32:64] = 32 zero bytes

   nonce_raw            base64url-decoded client nonce (16..64 bytes)
   tls_spki_der         DER SubjectPublicKeyInfo of the serving TLS certificate
   receipt_spki_der     DER SubjectPublicKeyInfo of the ES256 receipt key
   ehbp_receiver_pubkey raw 32-byte X25519 HPKE receiver key (empty if EHBP is off)

   The fields are concatenated without length prefixes. The verifier therefore
   also checks the encodings it feeds in: the nonce is the exact one it chose,
   the receipt SPKI is a 91-byte P-256 key, the EHBP key is 32 bytes, and the
   TLS SPKI parses as a public key whose hash is the published tls_spki_sha256.

2. Key attestation (/.well-known/adverserial-key-attestation):

       report_data = SHA-512( "adverserial-key-attestation-v1\\n" || statement )

   where statement is the exact canonical-JSON byte string that lists the
   receipt, meter and EHBP public keys and the TLS SPKI hash.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import canonjson

ATTESTATION_DOMAIN = b"adverserial-attestation-v2\x00"
KEY_ATTESTATION_DOMAIN = b"adverserial-key-attestation-v1\n"
P256_SPKI_LEN = 91
X25519_LEN = 32


def validate_nonce(nonce: str) -> bytes:
    if not nonce or len(nonce) > 96:
        raise ValueError("nonce is empty or too long")
    raw = canonjson.b64url_decode(nonce)
    if not 16 <= len(raw) <= 64:
        raise ValueError("nonce must decode to 16-64 bytes")
    return raw


def receipt_spki_der(jwk: dict) -> bytes:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("receipt key is not an EC P-256 JWK")
    x = int.from_bytes(canonjson.b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(canonjson.b64url_decode(jwk["y"]), "big")
    key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint of a P-256 JWK (this is the receipt key id)."""
    canonical = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (jwk["x"], jwk["y"])
    return canonjson.b64url(hashlib.sha256(canonical.encode()).digest())


def attestation_report_data(nonce_raw: bytes, tls_spki_der: bytes, receipt_spki: bytes, ehbp_pub: bytes) -> bytes:
    h = hashlib.sha256()
    for part in (ATTESTATION_DOMAIN, nonce_raw, tls_spki_der, receipt_spki, ehbp_pub):
        h.update(part)
    return h.digest() + bytes(32)


def key_attestation_report_data(statement: bytes) -> bytes:
    return hashlib.sha512(KEY_ATTESTATION_DOMAIN + statement).digest()


def spki_hash(spki_der: bytes) -> str:
    return "sha256:" + canonjson.b64url(hashlib.sha256(spki_der).digest())
