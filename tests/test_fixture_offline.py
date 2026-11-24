"""Offline tests against private fixtures. Skipped unless the fixtures exist
(see conftest.py). The fixtures are read in place and never copied into the
repository; assertions print hashes and check names only."""
import datetime as dt
import hashlib
import json

import pytest

import canonicalize_app_compose
import chainlib
import check_no_secrets
import record
import verify as cli
from avlib import binding, canonjson, checks, compose, dcap, eventlog, quote
from conftest import ROOT, fixture_path, fixture_value, require


def load_attestation():
    return json.loads(require("AV_FIXTURE_ATTESTATION").read_text())


def test_compose_hash_rule_reproduces_the_known_hash():
    """PROOF of the hashing rule: canonical(app-compose) hashes to the hash Phala reports."""
    snapshot = json.loads(require("AV_FIXTURE_CVM").read_text())
    raw = compose.canonical_app_compose(snapshot["compose_file"])
    assert compose.sha256_hex(raw) == snapshot["compose_hash"]
    expected = fixture_value("AV_FIXTURE_COMPOSE_HASH")
    if expected:
        assert snapshot["compose_hash"].startswith(expected)
    # and the documented sub-hashes of the same API object
    assert compose.sha256_hex(snapshot["compose_file"]["docker_compose_file"].encode()) == snapshot["docker_compose_hash"]
    # any deviation from the rule gives a different hash
    obj = snapshot["compose_file"]
    assert compose.sha256_hex(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()) != snapshot["compose_hash"]
    assert compose.sha256_hex(json.dumps({k: v for k, v in obj.items() if v is not None}, separators=(",", ":")).encode()) != snapshot["compose_hash"]


def test_compose_hash_is_the_measured_one():
    snapshot = json.loads(require("AV_FIXTURE_CVM").read_text())
    events = eventlog.load(load_attestation()["evidence"]["tdx_event_log"])
    facts = eventlog.runtime_facts(events)
    assert facts["compose-hash"] == snapshot["compose_hash"]
    assert facts["app-id"] == snapshot["app_id"] and facts["os-image-hash"] == snapshot["os"]["os_image_hash"]


def test_self_referential_compose_digest():
    snapshot = json.loads(require("AV_FIXTURE_CVM").read_text())
    declared, computed = compose.self_digest(snapshot["compose_file"]["docker_compose_file"])
    assert declared == computed
    att = fixture_path("AV_FIXTURE_ATTESTATION")
    if att:
        assert json.loads(att.read_text())["evidence"]["workload"]["compose_digest"] == computed


def test_fixture_compose_contains_secrets_and_tools_refuse_it(tmp_path, capsys):
    cvm = require("AV_FIXTURE_CVM")
    text = json.loads(cvm.read_text())["compose_file"]["docker_compose_file"]
    findings = check_no_secrets.scan_text(text)
    assert len(findings) >= 5
    for _, _, description in findings:
        assert len(description) < 120  # names and lengths only
    assert canonicalize_app_compose.main([str(cvm), "--out", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()
    capsys.readouterr()


def test_sample_attestation_has_no_credentials():
    att = require("AV_FIXTURE_ATTESTATION")
    assert check_no_secrets.scan_file(att, "evidence") == []


def test_report_data_binding_on_real_quote():
    ev = load_attestation()["evidence"]
    q = quote.parse(bytes.fromhex(ev["tdx_quote"]))
    expected = binding.attestation_report_data(
        binding.validate_nonce(ev["nonce"]), canonjson.b64url_decode(ev["tls_spki_der"]),
        binding.receipt_spki_der(ev["receipt_pubkey_jwk"]), canonjson.b64url_decode(ev["ehbp"]["public_key"]))
    assert q.fields["report_data"] == expected
    assert q.fields["report_data"][32:] == bytes(32)


def test_real_quote_chains_to_pinned_intel_root():
    ev = load_attestation()["evidence"]
    q = quote.parse(bytes.fromhex(ev["tdx_quote"]))
    at = dt.datetime.fromisoformat(ev["issued_at"].replace("Z", "+00:00"))
    info = quote.verify_signature_chain(q, at)
    assert info["root_sha256"] == quote.PINNED_ROOT_SHA256
    tampered = bytearray(q.raw)
    tampered[48 + 520] ^= 1  # report_data
    with pytest.raises(quote.QuoteError):
        quote.verify_signature_chain(quote.parse(bytes(tampered)), at)


def test_real_event_log_replays_to_quoted_rtmrs():
    ev = load_attestation()["evidence"]
    q = quote.parse(bytes.fromhex(ev["tdx_quote"]))
    mrs = eventlog.replay(eventlog.load(ev["tdx_event_log"]))
    assert [mrs[i] for i in range(4)] == [q.hex("rtmr%d" % i) for i in range(4)]


def _collateral_time(collateral: str) -> dt.datetime:
    issued, _ = dcap.collateral_window(collateral)
    return dt.datetime.fromisoformat(issued.replace("Z", "+00:00")) + dt.timedelta(hours=1)


def test_full_verifier_on_sample(tmp_path):
    att, policy = require("AV_FIXTURE_ATTESTATION", "AV_FIXTURE_POLICY")
    argv = ["--file", str(att), "--policy", str(policy), "--offline", "--json"]
    collateral = fixture_path("AV_FIXTURE_COLLATERAL")
    cvm = fixture_path("AV_FIXTURE_CVM")
    if collateral:
        argv += ["--collateral", str(collateral), "--at", _collateral_time(collateral.read_text()).strftime("%Y-%m-%dT%H:%M:%SZ")]
    if cvm:  # derive the deployment files in a temp dir outside the repository
        snapshot = json.loads(cvm.read_text())
        (tmp_path / "app-compose.json").write_bytes(compose.canonical_app_compose(snapshot["compose_file"]))
        (tmp_path / "docker-compose.yml").write_text(snapshot["compose_file"]["docker_compose_file"], newline="")
        argv += ["--app-compose", str(tmp_path / "app-compose.json"), "--docker-compose", str(tmp_path / "docker-compose.yml")]
    args = cli.build_parser().parse_args(argv)
    try:
        inp, _ = cli.gather(args)
    finally:  # the derived files contain the fixture's secrets: do not leave them behind
        for name in ("app-compose.json", "docker-compose.yml"):
            (tmp_path / name).unlink(missing_ok=True)
    result = checks.run(inp)
    st = {c["id"]: c["status"] for c in result.checks}
    must_pass = ["evidence.format", "tdx.quote_signature", "tdx.not_debug", "binding.report_data", "binding.ehbp_key",
                 "eventlog.replay", "eventlog.boot_order", "policy.mrtd", "policy.rtmr0", "policy.rtmr1", "policy.rtmr2",
                 "policy.os_image_hash", "policy.app_id", "policy.compose_hash", "policy.workload", "receipt.signature",
                 "gpu.evidence"]
    if collateral:
        must_pass.append("tdx.collateral_tcb")
    if cvm:
        must_pass += ["compose.app_compose_hash", "compose.docker_compose", "compose.self_digest", "compose.images_pinned"]
        # rc.30 passes signing seeds and the HPKE identity in from the compose: the verifier must say so.
        assert st["compose.keys_in_enclave"] == "FAIL"
    assert {k: st[k] for k in must_pass if st[k] != "PASS"} == {}
    for na in ("binding.nonce", "binding.freshness", "tls.live_spki", "keys.hpke_endpoint", "gpu.bound_to_vm"):
        assert st[na] == "N/A"
    assert st["gpu.signatures"] == "SKIP" and st["keyatt.report_data"] == "SKIP"
    assert result.summary["gpu"]["gpu_count"] >= 8
    assert result.verdict == ("FAIL" if cvm else "INCOMPLETE")


def test_tampered_sample_fails(tmp_path):
    att, policy = require("AV_FIXTURE_ATTESTATION", "AV_FIXTURE_POLICY")
    doc = json.loads(att.read_text())
    doc["evidence"]["nonce"] = canonjson.b64url(b"\x01" * 32)
    inp = checks.Inputs(response=doc, policy=json.loads(policy.read_text()), mode="file",
                        at=dt.datetime.fromisoformat(doc["evidence"]["issued_at"].replace("Z", "+00:00")))
    st = {c["id"]: c["status"] for c in checks.run(inp).checks}
    assert st["binding.report_data"] == "FAIL" and st["receipt.signature"] == "FAIL" and st["tdx.quote_signature"] == "PASS"


def test_recorder_on_sample(tmp_path, capsys):
    att, policy = require("AV_FIXTURE_ATTESTATION", "AV_FIXTURE_POLICY")
    root = tmp_path / "repo"
    release = root / "deployments" / "fixture-release"
    release.mkdir(parents=True)
    (release / "policy.json").write_bytes(policy.read_bytes())
    (root / "deployments" / "CURRENT").write_text("fixture-release\n")
    (root / "history").mkdir()
    extra = []
    at = json.loads(att.read_text())["evidence"]["issued_at"]
    collateral = fixture_path("AV_FIXTURE_COLLATERAL")
    if collateral:
        extra = ["--collateral", str(collateral)]
        at = _collateral_time(collateral.read_text()).strftime("%Y-%m-%dT%H:%M:%SZ")
    code = record.main(["--root", str(root), "--file", str(att), "--at", at, "--offline", *extra])
    capsys.readouterr()
    assert code == 2  # INCOMPLETE: no compose files, no NVIDIA keys, no key attestation - but nothing failed
    count, _ = chainlib.validate(root / "history" / "attestations.jsonl", root)
    (entry,) = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert count == 1 and entry["verdict"] == "INCOMPLETE" and entry["failed"] == []
    assert entry["deployment"] == "fixture-release"
    assert entry["evidence_sha256"] == hashlib.sha256(att.read_bytes()).hexdigest()
    if collateral:
        assert entry["tcb_status"] == "UpToDate" and "tdx.collateral_tcb" not in entry["skipped"]
    assert check_no_secrets.main(["--profile", "evidence", str(root / "history")]) == 0
    capsys.readouterr()
    assert not any(p.name.startswith("sample-") for p in ROOT.rglob("*.json"))
