"""Intel TDX quote (version 4, TD 1.0 body) parsing and signature-chain check.

This is a deliberately small, readable second implementation that needs no
network: it proves that the quote was signed by an attestation key that an
Intel-certified Quoting Enclave vouched for, on a platform whose PCK
certificate chains to the Intel SGX Root CA pinned in ../trust/.

It does NOT evaluate revocation lists, the TCB level, or the Quoting Enclave
identity. Those need Intel-signed collateral and are done by dcap-qvl in
dcap.py. A deployment is only "verified" when both layers pass.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

HEADER_LEN = 48
BODY_LEN = 584
SIGNED_LEN = HEADER_LEN + BODY_LEN  # 632 bytes covered by the quote signature
TEE_TDX = 0x81
PINNED_ROOT = Path(__file__).resolve().parent.parent / "trust" / "intel_sgx_root_ca.pem"
# SHA-256 of the DER certificate "CN=Intel SGX Root CA" (valid 2018-05-21 .. 2049-12-31),
# as downloaded from certificates.trustedservices.intel.com.
PINNED_ROOT_SHA256 = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"

# (name, offset inside the TD report body, length)
_BODY_FIELDS = [
    ("tee_tcb_svn", 0, 16), ("mr_seam", 16, 48), ("mr_signer_seam", 64, 48),
    ("seam_attributes", 112, 8), ("td_attributes", 120, 8), ("xfam", 128, 8),
    ("mrtd", 136, 48), ("mr_config_id", 184, 48), ("mr_owner", 232, 48),
    ("mr_owner_config", 280, 48), ("rtmr0", 328, 48), ("rtmr1", 376, 48),
    ("rtmr2", 424, 48), ("rtmr3", 472, 48), ("report_data", 520, 64),
]


class QuoteError(Exception):
    pass


@dataclass
class Quote:
    raw: bytes
    version: int
    tee_type: int
    fields: dict  # name -> bytes
    signature: bytes  # 64 bytes r||s over raw[:632]
    attestation_key: bytes  # 64 bytes x||y, P-256
    qe_report: bytes  # 384 bytes
    qe_report_signature: bytes
    qe_auth_data: bytes
    pck_chain_pem: bytes

    def hex(self, name: str) -> str:
        return self.fields[name].hex()

    @property
    def debug(self) -> bool:
        return bool(self.fields["td_attributes"][0] & 1)


def parse(raw: bytes) -> Quote:
    if len(raw) < SIGNED_LEN + 4:
        raise QuoteError("quote is too short")
    version, key_type, tee_type = struct.unpack_from("<HHI", raw, 0)
    if version != 4:
        raise QuoteError("unsupported quote version %d (this verifier handles v4)" % version)
    if tee_type != TEE_TDX:
        raise QuoteError("not a TDX quote (tee_type=0x%x)" % tee_type)
    if key_type != 2:
        raise QuoteError("unsupported attestation key type %d (expected ECDSA P-256)" % key_type)
    body = raw[HEADER_LEN:SIGNED_LEN]
    fields = {name: body[off:off + ln] for name, off, ln in _BODY_FIELDS}
    (sig_len,) = struct.unpack_from("<I", raw, SIGNED_LEN)
    sig = raw[SIGNED_LEN + 4:SIGNED_LEN + 4 + sig_len]
    if len(sig) != sig_len or sig_len < 134:
        raise QuoteError("truncated quote signature data")
    cert_type, cert_size = struct.unpack_from("<HI", sig, 128)
    if cert_type != 6:
        raise QuoteError("unexpected certification data type %d (expected 6)" % cert_type)
    cd = sig[134:134 + cert_size]
    if len(cd) != cert_size or cert_size < 384 + 64 + 2 + 6:
        raise QuoteError("truncated QE certification data")
    (auth_len,) = struct.unpack_from("<H", cd, 448)
    off = 450 + auth_len
    inner_type, inner_size = struct.unpack_from("<HI", cd, off)
    if inner_type != 5:
        raise QuoteError("unexpected inner certification data type %d (expected PCK chain)" % inner_type)
    pem = cd[off + 6:off + 6 + inner_size]
    if len(pem) != inner_size:
        raise QuoteError("truncated PCK certificate chain")
    return Quote(raw=raw, version=version, tee_type=tee_type, fields=fields,
                 signature=sig[0:64], attestation_key=sig[64:128],
                 qe_report=cd[0:384], qe_report_signature=cd[384:448],
                 qe_auth_data=cd[450:450 + auth_len], pck_chain_pem=pem)


def _p256(xy: bytes) -> ec.EllipticCurvePublicKey:
    x, y = int.from_bytes(xy[:32], "big"), int.from_bytes(xy[32:], "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _verify_raw(key, sig: bytes, data: bytes, what: str) -> None:
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        key.verify(der, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise QuoteError("%s signature is invalid" % what) from None


def _cn(cert: x509.Certificate) -> str:
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return names[0].value if names else cert.subject.rfc4514_string()


def load_pinned_root(path: Path = PINNED_ROOT) -> x509.Certificate:
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    if path == PINNED_ROOT and fp != PINNED_ROOT_SHA256:
        raise QuoteError("the pinned Intel root certificate file was modified")
    return cert


def verify_signature_chain(q: Quote, at: dt.datetime, root: x509.Certificate | None = None) -> dict:
    """Raise QuoteError unless the quote chains to the pinned Intel root at time `at`."""
    root = root or load_pinned_root()
    certs = x509.load_pem_x509_certificates(q.pck_chain_pem.rstrip(b"\x00"))
    if len(certs) != 3:
        raise QuoteError("expected a 3-certificate PCK chain, got %d" % len(certs))
    leaf, inter, chain_root = certs
    der = serialization.Encoding.DER
    if chain_root.public_bytes(der) != root.public_bytes(der):
        raise QuoteError("PCK chain does not end at the pinned Intel SGX Root CA")
    for cert in certs:
        if not (cert.not_valid_before_utc <= at <= cert.not_valid_after_utc):
            raise QuoteError("certificate %s is not valid at %s" % (cert.subject.rfc4514_string(), at.isoformat()))
    try:
        root.verify_directly_issued_by(root)
        inter.verify_directly_issued_by(root)
        leaf.verify_directly_issued_by(inter)
    except Exception as exc:  # cryptography raises several types here
        raise QuoteError("PCK certificate chain is invalid: %s" % exc) from None
    # 1. The platform's PCK key signed the Quoting Enclave report.
    _verify_raw(leaf.public_key(), q.qe_report_signature, q.qe_report, "QE report")
    # 2. The QE report commits to the attestation key.
    expected = hashlib.sha256(q.attestation_key + q.qe_auth_data).digest()
    if q.qe_report[320:352] != expected:
        raise QuoteError("QE report does not commit to the quote's attestation key")
    # 3. The attestation key signed header + TD report body.
    _verify_raw(_p256(q.attestation_key), q.signature, q.raw[:SIGNED_LEN], "quote")
    return {
        "pck_issuer": _cn(inter),
        "root_sha256": hashlib.sha256(root.public_bytes(der)).hexdigest(),
        "qe_mrsigner": q.qe_report[128:160].hex(),
    }
