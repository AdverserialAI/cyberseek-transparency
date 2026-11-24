"""Builds a complete, entirely synthetic deployment for tests.

Nothing here comes from a real machine: the "Intel root", the PCK chain, the
quote, the NVIDIA signing key and every application key are generated on the
spot. The byte layouts follow the real formats, so the verifier's parsing,
signature checking, bindings and replay logic are exercised end to end without
network access or private fixtures. The throwaway root is handed to the
verifier through Inputs.trust_root, which the command line cannot set.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from avlib import binding, canonjson, checks, compose, eventlog, gpu

NOW = dt.datetime(2030, 1, 15, 12, 0, 0, tzinfo=dt.timezone.utc)
APP_ID = "ab" * 20
OS_IMAGE_HASH = "cd" * 32


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def raw_sig(key, data: bytes, alg=hashes.SHA256(), size=32) -> bytes:
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(alg)))
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _cert(subject, issuer_name, pub, signer, ca):
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
            .public_key(pub).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=30)).not_valid_after(NOW + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(signer, hashes.SHA256()))


class Platform:
    """A fake TDX platform: root CA -> intermediate -> PCK leaf, plus an attestation key."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        self.pck_key = ec.generate_private_key(ec.SECP256R1())
        self.att_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert("Test Root CA", "Test Root CA", self.root_key.public_key(), self.root_key, True)
        inter = _cert("Test Platform CA", "Test Root CA", self.inter_key.public_key(), self.root_key, True)
        leaf = _cert("Test PCK", "Test Platform CA", self.pck_key.public_key(), self.inter_key, False)
        pem = serialization.Encoding.PEM
        self.chain_pem = leaf.public_bytes(pem) + inter.public_bytes(pem) + self.root.public_bytes(pem)

    def quote(self, report_data: bytes, rtmrs: dict, mrtd: bytes = b"\x11" * 48, debug: bool = False) -> bytes:
        header = struct.pack("<HHI", 4, 2, 0x81) + bytes(40)
        body = bytearray(584)
        body[120:128] = bytes([1 if debug else 0]) + bytes(3) + b"\x10" + bytes(3)
        body[136:184] = mrtd
        for i in range(4):
            body[328 + 48 * i:376 + 48 * i] = bytes.fromhex(rtmrs[i])
        body[520:584] = report_data
        signed = header + bytes(body)
        numbers = self.att_key.public_key().public_numbers()
        att_pub = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
        auth = b"\x00" * 32
        qe_report = bytearray(384)
        qe_report[320:352] = hashlib.sha256(att_pub + auth).digest()
        qe_report = bytes(qe_report)
        cert_data = (qe_report + raw_sig(self.pck_key, qe_report) + struct.pack("<H", len(auth)) + auth
                     + struct.pack("<HI", 5, len(self.chain_pem)) + self.chain_pem)
        sig_data = raw_sig(self.att_key, signed) + att_pub + struct.pack("<HI", 6, len(cert_data)) + cert_data
        return signed + struct.pack("<I", len(sig_data)) + sig_data


def runtime_event(name: str, payload: bytes = b"") -> dict:
    e = {"imr": 3, "event_type": eventlog.RUNTIME_EVENT_TYPE, "event": name, "event_payload": payload.hex()}
    e["digest"] = eventlog.runtime_digest(e).hex()
    return e


def make_event_log(compose_hash: str, gpu_policy_hash: str | None = None, gpu_attestation: bytes | None = None) -> list:
    """dstack 0.5.x order by default; with a GPU policy hash, the order dstack 0.6.x writes."""
    events = _make_event_log(compose_hash)
    if gpu_policy_hash is None:
        return events
    names = [e["event"] for e in events]
    events.insert(names.index("instance-id"), runtime_event("gpu-policy-hash", bytes.fromhex(gpu_policy_hash)))
    tail = ([runtime_event("gpu-attestation", gpu_attestation)] if gpu_attestation is not None else []) + [
        runtime_event("storage-fs", b"zfs"), runtime_event("storage-encrypted", b"1")]
    return events[:-1] + tail + events[-1:]


def _make_event_log(compose_hash: str) -> list:
    boot = [{"imr": i, "event_type": 4, "digest": hashlib.sha384(b"boot%d%d" % (i, n)).hexdigest(), "event": "", "event_payload": ""}
            for i in range(3) for n in range(2)]
    return boot + [
        runtime_event("system-preparing"),
        runtime_event("app-id", bytes.fromhex(APP_ID)),
        runtime_event("compose-hash", bytes.fromhex(compose_hash)),
        runtime_event("instance-id", b"\x01" * 20),
        runtime_event("boot-mr-done"),
        runtime_event("os-image-hash", bytes.fromhex(OS_IMAGE_HASH)),
        runtime_event("key-provider", b'{"name":"kms","id":"00"}'),
        runtime_event("system-ready"),
    ]


PROXY_DIGEST, INFERENCE_DIGEST, HELPER_DIGEST = "sha256:" + "aa" * 32, "sha256:" + "bb" * 32, "sha256:" + "cc" * 32
SEALED = ["CLOUDFLARE_API_TOKEN", "HF_TOKEN", "METER_INGRESS_SHARED_SECRET", "NV_ATTESTATION_SERVICE_KEY"]
PROXY_VERSION = "v0.0.0-test"

# Same shape as the first enclave-key release: the proxy is the only published
# service, the model server sits on an internal network, the proxy-to-inference
# credential is generated inside the VM, and four sealed variables are referenced.
COMPOSE_TEMPLATE = r"""name: dstack
services:
  attest-proxy:
    cap_drop:
    - ALL
    environment:
      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}
      COMPOSE_DIGEST: sha256:SELF
      CONFIDENTIAL_MODE: '1'
      ENCLAVE_KEY_DIR: /state/keys
      ENTITLEMENT_JWKS_JSON: '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}'
      METER_INGRESS_SHARED_SECRET: ${METER_INGRESS_SHARED_SECRET}
      UPSTREAM: http://sglang:30000
      UPSTREAM_BEARER_TOKEN_FILE: /run/handoff/upstream-token
    image: ghcr.io/example/attest-proxy@PROXY_DIGEST
    networks:
      default: null
      inference: null
    ports:
    - mode: ingress
      target: 8443
      published: '443'
      protocol: tcp
    volumes:
    - type: volume
      source: inference-handoff
      target: /run/handoff
      read_only: true
      volume: {}
  gpu-evidence-collector:
    environment:
      NV_ATTESTATION_SERVICE_KEY: ${NV_ATTESTATION_SERVICE_KEY}
    image: ghcr.io/example/collector@HELPER_DIGEST
    networks:
      default: null
  model-download:
    command:
    - "set -euo pipefail; marker=\"/data/.done-$${MODEL_REVISION}\"; test -f \"$$marker\""
    environment:
      HF_TOKEN: ${HF_TOKEN}
      MODEL_REVISION: 0123456789abcdef
    image: example/helper@HELPER_DIGEST
    networks:
      default: null
  inference-auth-init:
    image: example/helper@HELPER_DIGEST
    entrypoint:
    - python3
    - -c
    command:
    - |
      import os, secrets
      with open('/handoff/upstream-token', 'w') as f:
          f.write(secrets.token_urlsafe(48))
    network_mode: none
    volumes:
    - type: volume
      source: inference-handoff
      target: /handoff
      volume: {}
  sglang:
    image: example/inference@INFERENCE_DIGEST
    entrypoint:
    - /bin/bash
    - -c
    command:
    - |
      set -u
      KEY="$$(head -c 200 /run/handoff/upstream-token | tr -d '\r\n')"
      if [ "$${#KEY}" -lt 32 ]; then exit 1; fi
      set -- "$$@" --api-key "$$KEY"
      exec python3 -m sglang.launch_server "$$@"
    - 'sglang'
    - '--port'
    - '30000'
    networks:
      inference: null
    volumes:
    - type: volume
      source: inference-handoff
      target: /run/handoff
      read_only: true
      volume: {}
networks:
  default:
    name: dstack_default
  inference:
    name: dstack_inference
    internal: true
volumes:
  inference-handoff:
    name: dstack_inference-handoff
"""


def finish_compose(template: str, allowed_envs=None, manifest_version=2, gpu_policy=None) -> tuple[str, bytes]:
    """Fill in the image digests and the self-referential digest; return (compose text, canonical app-compose bytes).

    manifest_version 2 is the dstack 0.5.x shape; "3" (a string) with a
    gpu_policy is the dstack 0.6.x shape, where `"init_script":[]` is part of
    the measured bytes."""
    for name, value in (("PROXY_DIGEST", PROXY_DIGEST), ("INFERENCE_DIGEST", INFERENCE_DIGEST), ("HELPER_DIGEST", HELPER_DIGEST)):
        template = template.replace("@" + name, "@" + value)
    digest = hashlib.sha256(template.encode()).hexdigest()
    text = template.replace("sha256:SELF", "sha256:" + digest)
    app = {"allowed_envs": list(SEALED if allowed_envs is None else allowed_envs), "docker_compose_file": text, "kms_enabled": True,
           "manifest_version": manifest_version, "name": "", "runner": "docker-compose", "pre_launch_script": "#!/bin/sh\ntrue\n",
           "init_script": []}
    if gpu_policy is not None:
        app["requirements"] = {"gpu_policy": gpu_policy}
    return text, compose.canonical_app_compose(app)


def make_compose() -> tuple[str, bytes]:
    """A secret-free docker compose with a correct self-referential digest, and its app-compose."""
    return finish_compose(COMPOSE_TEMPLATE)


def make_gpu_bundle(count: int, at: dt.datetime) -> tuple[dict, dict]:
    key = ec.generate_private_key(ec.SECP384R1())
    n = key.public_key().public_numbers()
    jwks = {"keys": [{"kty": "EC", "crv": "P-384", "kid": "test-kid",
                      "x": b64u(n.x.to_bytes(48, "big")), "y": b64u(n.y.to_bytes(48, "big"))}]}
    nonce, iat = "ee" * 32, int(at.timestamp()) - 120

    def token(claims):
        claims = dict(claims, iss=gpu.NRAS_ORIGIN, iat=iat, exp=iat + 3600, eat_nonce=nonce)
        head = b64u(json.dumps({"alg": "ES384", "kid": "test-kid"}).encode()) + "." + b64u(json.dumps(claims).encode())
        return head + "." + b64u(raw_sig(key, head.encode(), hashes.SHA384(), 48))

    per_gpu = [token({"hwmodel": "GH100", "measres": "success", "secboot": True, "dbgstat": "disabled", "ueid": str(i)})
               for i in range(count)]
    submods = {"GPU-%d" % i: ["DIGEST", ["SHA-256", hashlib.sha256(t.encode()).hexdigest()]] for i, t in enumerate(per_gpu)}
    overall = token({"sub": "NVIDIA-PLATFORM-ATTESTATION", "x-nvidia-overall-att-result": True, "submods": submods})
    stamp = (at - dt.timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle = {"version": 1, "verdict": "successful", "generated_at": stamp, "nonce": nonce, "nonce_source": "nras-sdk",
              "nras_url": gpu.NRAS_ORIGIN + "/v4/attest/gpu", "eat_jwts": [overall] + per_gpu, "gpus_attested": count + 1}
    return bundle, jwks


class Deployment:
    """Everything a verifier run needs, with mutable parts for tamper tests."""

    def __init__(self, gpus: int = 8, at: dt.datetime = NOW):
        self.at = at
        self.platform = Platform()
        self.tls_key = ec.generate_private_key(ec.SECP256R1())
        self.receipt_key = ec.generate_private_key(ec.SECP256R1())
        self.meter_key = ed25519.Ed25519PrivateKey.generate()
        self.keys_origin = "enclave-generated"
        self.ehbp_pub = os.urandom(32)
        self.compose_text, self.app_compose = make_compose()
        self.compose_hash = hashlib.sha256(self.app_compose).hexdigest()
        self.events = make_event_log(self.compose_hash)
        self.rtmrs = eventlog.replay(self.events)
        self.nonce = b64u(os.urandom(32))
        self.gpu_bundle, self.jwks = make_gpu_bundle(gpus, at)

    # -- keys ------------------------------------------------------------
    @property
    def tls_spki(self) -> bytes:
        return self.tls_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def receipt_jwk(self) -> dict:
        n = self.receipt_key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        jwk["kid"] = binding.jwk_thumbprint(jwk)
        return jwk

    @property
    def meter_jwk(self) -> dict:
        """Same members as attest-proxy internal/meter Signer.PublicJWK()."""
        raw = self.meter_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw), "kid": b64u(hashlib.sha256(raw).digest()), "use": "sig", "alg": "EdDSA"}

    def use_compose(self, text: str, app_compose: bytes):
        """Switch to another compose (tamper tests): the measurements follow it."""
        self.compose_text, self.app_compose = text, app_compose
        self.compose_hash = hashlib.sha256(app_compose).hexdigest()
        self.events = make_event_log(self.compose_hash)
        self.rtmrs = eventlog.replay(self.events)
        return self

    def use_os_065(self, gpu_policy=None, gpu_attestation: bytes | None = None, pin: bool = True):
        """Switch to the dstack 0.6.x shape: manifest version "3" with a GPU policy, and the 0.6.x event order."""
        gpu_policy = {"attest_gpu": False} if gpu_policy is None else gpu_policy
        self.compose_text, self.app_compose = finish_compose(COMPOSE_TEMPLATE, manifest_version="3", gpu_policy=gpu_policy)
        self.compose_hash = hashlib.sha256(self.app_compose).hexdigest()
        self.gpu_policy_hash = compose.gpu_policy_hash(gpu_policy)
        self.pin_gpu_policy = pin
        self.events = make_event_log(self.compose_hash, self.gpu_policy_hash, gpu_attestation)
        self.rtmrs = eventlog.replay(self.events)
        return self

    # -- documents -------------------------------------------------------
    def policy(self) -> dict:
        declared, _ = compose.self_digest(self.compose_text)
        return {
            "policy_id": "test-policy", "model_id": "test/model", "proxy_version": PROXY_VERSION,
            "deployment_configuration_digest": declared, "model_artifact_digest": "sha256:" + "12" * 32,
            "runtime_image_digest": INFERENCE_DIGEST, "proxy_image_digest": PROXY_DIGEST,
            "allowed_runtime": {"minimum_gpu_count": 8},
            "freshness": {"gpu_evidence_max_age_seconds": 1800},
            "tdx": {"mrtd": "11" * 48, "rtmr0": self.rtmrs[0], "rtmr1": self.rtmrs[1], "rtmr2": self.rtmrs[2],
                    "app_id": APP_ID, "compose_hash": self.compose_hash, "os_image_hash": OS_IMAGE_HASH,
                    **({"gpu_policy_hash": self.gpu_policy_hash} if getattr(self, "pin_gpu_policy", False) else {})},
            "verifier": {"accepted_tcb_status": ["UpToDate"], "allowed_envs": list(SEALED),
                         "proxy_service": "attest-proxy", "inference_service": "sglang",
                         "enclave_key_proxy_digests": [PROXY_DIGEST]},
        }

    def response(self, nonce: str | None = None, debug: bool = False) -> dict:
        nonce = nonce or self.nonce
        jwk = self.receipt_jwk
        report_data = binding.attestation_report_data(canonjson.b64url_decode(nonce), self.tls_spki,
                                                      binding.receipt_spki_der(jwk), self.ehbp_pub)
        policy = self.policy()
        stamp = self.at.strftime("%Y-%m-%dT%H:%M:%SZ")
        evidence = {
            "version": 1, "nonce": nonce, "issued_at": stamp,
            "expires_at": (self.at + dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tdx_quote": self.platform.quote(report_data, self.rtmrs, debug=debug).hex(),
            "tdx_event_log": json.dumps(self.events),
            "tls_spki_sha256": binding.spki_hash(self.tls_spki), "tls_spki_der": b64u(self.tls_spki),
            "receipt_pubkey_jwk": jwk, "attestation_state_digest": "sha256:test",
            "ehbp": {"protocol": "ehbp-rfc9180-v1", "key_config": b64u(b"\x00\x00\x20" + self.ehbp_pub),
                     "public_key": b64u(self.ehbp_pub), "public_key_sha256": binding.spki_hash(self.ehbp_pub)},
            "workload": {"policy_id": policy["policy_id"], "model_id": policy["model_id"], "proxy_version": policy["proxy_version"],
                         "compose_digest": policy["deployment_configuration_digest"], "model_digest": policy["model_artifact_digest"]},
            "gpu_evidence": self.gpu_bundle, "gpu_evidence_ref": "nras-eat-bundle",
            "gpu_evidence_fresh_at": self.gpu_bundle["generated_at"],
        }
        return {"evidence": evidence, "verification_receipt": self.receipt(evidence)}

    def receipt(self, evidence: dict) -> str:
        header = canonjson.dumps({"alg": "ES256", "kid": self.receipt_jwk["kid"], "typ": "JWT"})
        claims = canonjson.dumps({"nonce": evidence["nonce"], "verdict": "verified", "evidence_sha256": canonjson.digest(evidence)})
        signing_input = b64u(header.encode()) + "." + b64u(claims.encode())
        return signing_input + "." + b64u(raw_sig(self.receipt_key, signing_input.encode()))

    def key_statement(self, **overrides) -> dict:
        """The fields of attest-proxy's keyAttestationStatement (internal/server/status.go)."""
        statement = {
            "type": "adverserial-key-attestation/v1",
            "issued_at": self.at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "proxy_version": PROXY_VERSION,
            "keys_origin": self.keys_origin,
            "receipt_pubkey_jwk": self.receipt_jwk,
            "meter_pubkey_jwk": self.meter_jwk,
            "ehbp_public_key": b64u(self.ehbp_pub),
            "ehbp_public_key_sha256": binding.spki_hash(self.ehbp_pub),
            "tls_spki_sha256": binding.spki_hash(self.tls_spki),
        }
        statement.update(overrides)
        return statement

    def key_attestation(self, statement: str | None = None, **overrides) -> dict:
        """Response of /.well-known/adverserial-key-attestation: {"statement", "quote", "event_log"}."""
        statement = canonjson.dumps(self.key_statement(**overrides)) if statement is None else statement
        report_data = hashlib.sha512(b"adverserial-key-attestation-v1\n" + statement.encode()).digest()
        return {"statement": statement, "quote": self.platform.quote(report_data, self.rtmrs).hex(), "event_log": json.dumps(self.events)}

    def meter_jwks(self) -> dict:
        return {"keys": [self.meter_jwk]}

    def statusz(self) -> dict:
        return {"version": PROXY_VERSION, "started_at": self.at.strftime("%Y-%m-%dT%H:%M:%SZ"), "keys_origin": self.keys_origin,
                "receipt_kid": self.receipt_jwk["kid"], "meter_kid": self.meter_jwk["kid"], "meter_jwk_thumbprint": "unused",
                "ehbp_public_key_sha256": binding.spki_hash(self.ehbp_pub), "upstream_ready": True, "ingress": {"in_use": 0, "max": 48}}

    def inputs(self, live: bool = True, **overrides) -> checks.Inputs:
        inp = checks.Inputs(
            response=self.response(), policy=self.policy(), mode="live" if live else "file", at=self.at,
            expected_nonce=self.nonce if live else None,
            live_spki=binding.spki_hash(self.tls_spki) if live else None,
            spki_seen=[binding.spki_hash(self.tls_spki)] * 3 if live else [],
            app_compose_raw=self.app_compose, docker_compose_text=self.compose_text,
            nras_jwks=self.jwks, hpke_keys_body=b"\x00\x00\x20" + self.ehbp_pub if live else None,
            key_attestation=self.key_attestation(), meter_jwks=self.meter_jwks() if live else None,
            statusz=self.statusz() if live else None, trust_root=self.platform.root)
        for k, v in overrides.items():
            setattr(inp, k, v)
        return inp


def statuses(result: checks.Result) -> dict:
    return {c["id"]: c["status"] for c in result.checks}
