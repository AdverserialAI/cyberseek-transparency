"""Agreement with the proxy's own output.

tests/vectors/key-attestation-rc32.json was produced by attest-proxy
v0.1.0-rc.32 itself: its key-attestation, meter-JWKS and statusz handlers
(internal/server/status.go) were run inside a Go test with throwaway keys and
the development quote source, whose "quote" is the 8 bytes DEVQTE00 followed by
the 64-byte report_data. It contains public keys only. It pins down the three
things this verifier cannot learn from its own synthetic data: the exact
statement fields, the proxy's canonical JSON, and the report_data rule.

The vector was not regenerated for v0.1.0-rc.33, the release that was
deployed: internal/server/status.go is byte-identical between the two tags
(`git diff v0.1.0-rc.32 v0.1.0-rc.33 -- internal/server` is empty), so the
proxy_version inside the vector is, correctly, still rc.32.
"""
import hashlib
import json

import synth
from avlib import binding, canonjson, checks
from conftest import ROOT

VECTOR = json.loads((ROOT / "tests" / "vectors" / "key-attestation-rc32.json").read_text())
KA = VECTOR["key_attestation"]
STATEMENT = json.loads(KA["statement"])


def test_response_shape():
    assert set(KA) == {"statement", "quote", "event_log"} and isinstance(KA["statement"], str)


def test_report_data_rule_matches_the_proxy():
    quote = bytes.fromhex(KA["quote"])
    assert quote[:8] == b"DEVQTE00"
    assert quote[8:72] == binding.key_attestation_report_data(KA["statement"].encode("utf-8"))
    assert quote[8:72] == hashlib.sha512(b"adverserial-key-attestation-v1\n" + KA["statement"].encode()).digest()


def test_canonical_json_matches_the_proxy():
    assert canonjson.dumps(STATEMENT) == KA["statement"]


def test_statement_fields_are_the_ones_the_verifier_and_the_synthetic_tests_use():
    assert set(STATEMENT) == {"type", "issued_at", "proxy_version", "keys_origin", "receipt_pubkey_jwk", "meter_pubkey_jwk",
                              "ehbp_public_key", "ehbp_public_key_sha256", "tls_spki_sha256"}
    ours = synth.Deployment().key_statement()
    assert set(ours) == set(STATEMENT)
    assert set(ours["receipt_pubkey_jwk"]) == set(STATEMENT["receipt_pubkey_jwk"])
    assert set(ours["meter_pubkey_jwk"]) == set(STATEMENT["meter_pubkey_jwk"])
    assert STATEMENT["type"] == checks.KEY_STATEMENT_TYPE and STATEMENT["keys_origin"] == checks.ENCLAVE_GENERATED
    assert STATEMENT["proxy_version"] == "v0.1.0-rc.32"


def test_key_identifiers_follow_the_rules_the_verifier_applies():
    receipt = STATEMENT["receipt_pubkey_jwk"]
    assert receipt["kid"] == binding.jwk_thumbprint(receipt) == VECTOR["receipt_kid"]
    assert canonjson.b64url(binding.receipt_spki_der(receipt)) == VECTOR["receipt_spki_der"]
    meter = STATEMENT["meter_pubkey_jwk"]
    assert meter["kid"] == canonjson.b64url(hashlib.sha256(canonjson.b64url_decode(meter["x"])).digest())
    ehbp = canonjson.b64url_decode(STATEMENT["ehbp_public_key"])
    assert len(ehbp) == 32 and STATEMENT["ehbp_public_key_sha256"] == binding.spki_hash(ehbp)
    assert STATEMENT["ehbp_public_key"] == VECTOR["ehbp_public_key"]
    assert STATEMENT["tls_spki_sha256"] == VECTOR["tls_spki_sha256"]


def test_meter_jwks_and_statusz_agree_with_the_statement():
    assert VECTOR["meter_jwks"] == {"keys": [STATEMENT["meter_pubkey_jwk"]]}
    sz = VECTOR["statusz"]
    assert sz["version"] == STATEMENT["proxy_version"] and sz["keys_origin"] == STATEMENT["keys_origin"]
    assert sz["receipt_kid"] == STATEMENT["receipt_pubkey_jwk"]["kid"]
    assert sz["ehbp_public_key_sha256"] == STATEMENT["ehbp_public_key_sha256"]
    assert sz["meter_kid"] == STATEMENT["meter_pubkey_jwk"]["kid"]


def test_verifier_accepts_the_proxy_statement_inside_a_tdx_shaped_quote(deployment, fake_dcap):
    """The proxy's statement bytes, quoted by the synthetic platform: the report_data and
    canonical-form checks pass on them; the key comparison fails because these are other keys."""
    doc = {"statement": KA["statement"], "event_log": json.dumps(deployment.events),
           "quote": deployment.platform.quote(bytes.fromhex(KA["quote"])[8:72], deployment.rtmrs).hex()}
    inp = deployment.inputs(collateral_json=fake_dcap, key_attestation=doc, meter_jwks=VECTOR["meter_jwks"])
    st = synth.statuses(checks.run(inp))
    assert st["keyatt.report_data"] == st["keyatt.quote"] == st["keyatt.keys_origin"] == st["keyatt.meter_key"] == "PASS"
    assert st["keyatt.keys_match"] == "FAIL" and st["keyatt.statement"] == "FAIL"   # other keys, other time and version


def test_development_quote_is_never_accepted(deployment, fake_dcap):
    inp = deployment.inputs(collateral_json=fake_dcap, key_attestation=KA)
    assert synth.statuses(checks.run(inp))["keyatt.report_data"] == "FAIL"
