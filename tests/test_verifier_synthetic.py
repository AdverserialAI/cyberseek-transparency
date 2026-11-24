"""End-to-end verifier behaviour on a fully synthetic deployment (see synth.py)."""
import datetime as dt
import json

import pytest

import synth
from avlib import checks, eventlog
from synth import statuses


def run(inp):
    return checks.run(inp)


def test_everything_passes_live(deployment, fake_dcap):
    result = run(deployment.inputs(collateral_json=fake_dcap))
    st = statuses(result)
    assert [k for k, v in st.items() if v not in ("PASS", "N/A")] == [], result.to_json()
    assert st["gpu.bound_to_vm"] == "N/A"  # stated limitation, never a PASS
    assert result.verdict == "PASS"
    s = result.summary
    assert s["compose_hash"] == deployment.compose_hash and s["measurements"]["rtmr3"] == deployment.rtmrs[3]
    assert s["keys"]["receipt_kid"] == deployment.receipt_jwk["kid"] and s["gpu"]["gpu_count"] == 8


def test_without_collateral_verdict_is_incomplete_not_pass(deployment):
    result = run(deployment.inputs())
    st = statuses(result)
    assert st["tdx.quote_signature"] == "PASS" and st["tdx.collateral_tcb"] == "SKIP" and st["keyatt.quote"] == "SKIP"
    assert result.verdict == "INCOMPLETE"


def test_file_mode_marks_freshness_and_tls_not_applicable(deployment, fake_dcap):
    result = run(deployment.inputs(live=False, collateral_json=fake_dcap))
    st = statuses(result)
    assert st["binding.nonce"] == st["binding.freshness"] == st["tls.live_spki"] == st["keys.hpke_endpoint"] == "N/A"
    assert result.verdict == "PASS" and result.mode == "file"


def test_quote_not_signed_under_the_pinned_intel_root_fails(deployment):
    st = statuses(run(deployment.inputs(trust_root=None)))  # None = real pinned Intel root
    assert st["tdx.quote_signature"] == "FAIL"


def test_tampered_quote_body_fails_signature(deployment):
    inp = deployment.inputs()
    raw = bytearray.fromhex(inp.response["evidence"]["tdx_quote"])
    raw[48 + 136] ^= 1  # first byte of MRTD
    inp.response["evidence"]["tdx_quote"] = raw.hex()
    st = statuses(run(inp))
    assert st["tdx.quote_signature"] == "FAIL" and st["policy.mrtd"] == "FAIL"


def test_out_of_date_tcb_fails(deployment, fake_dcap):
    result = run(deployment.inputs(collateral_json=json.dumps({"status": "OutOfDate"})))
    assert statuses(result)["tdx.collateral_tcb"] == "FAIL" and result.verdict == "FAIL"
    # ... unless the policy explicitly accepts that status
    inp = deployment.inputs(collateral_json=json.dumps({"status": "OutOfDate"}))
    inp.policy["verifier"]["accepted_tcb_status"] = ["UpToDate", "OutOfDate"]
    assert statuses(run(inp))["tdx.collateral_tcb"] == "PASS"


def test_debug_td_fails(deployment):
    inp = deployment.inputs()
    inp.response = deployment.response(debug=True)
    assert statuses(run(inp))["tdx.not_debug"] == "FAIL"


def test_dev_mode_evidence_is_rejected(deployment):
    inp = deployment.inputs()
    inp.response["evidence"]["dev"] = True
    result = run(inp)
    assert statuses(result) == {"policy.not_pending": "PASS", "evidence.format": "FAIL"} and result.verdict == "FAIL"


def test_replayed_evidence_with_another_nonce_fails(deployment):
    inp = deployment.inputs(expected_nonce=synth.b64u(b"\x07" * 32))
    assert statuses(run(inp))["binding.nonce"] == "FAIL"


def test_swapped_keys_break_report_data(deployment):
    for field, value in (("tls_spki_der", None), ("ehbp", None), ("receipt_pubkey_jwk", None)):
        other = synth.Deployment()
        inp = deployment.inputs()
        ev = inp.response["evidence"]
        donor = other.response()["evidence"]
        ev[field] = donor[field]
        if field == "tls_spki_der":
            ev["tls_spki_sha256"] = donor["tls_spki_sha256"]
        assert statuses(run(inp))["binding.report_data"] == "FAIL", field


def test_stale_timestamp_fails_live(deployment):
    inp = deployment.inputs(at=deployment.at + dt.timedelta(minutes=20))
    assert statuses(run(inp))["binding.freshness"] == "FAIL"


def test_event_log_tampering_fails_replay(deployment):
    inp = deployment.inputs()
    events = json.loads(inp.response["evidence"]["tdx_event_log"])
    target = next(e for e in events if e.get("event") == "compose-hash")
    forged = synth.runtime_event("compose-hash", b"\x99" * 32)
    target.update(forged)
    inp.response["evidence"]["tdx_event_log"] = json.dumps(events)
    st = statuses(run(inp))
    assert st["eventlog.replay"] == "FAIL"


def test_policy_mismatches_fail_individually(deployment):
    for key in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "app_id", "compose_hash", "os_image_hash"):
        inp = deployment.inputs()
        inp.policy["tdx"][key] = "00" * (len(inp.policy["tdx"][key]) // 2)
        st = statuses(run(inp))
        assert st["policy." + key] == "FAIL", key
        assert [k for k, v in st.items() if k.startswith("policy.") and v == "FAIL"] == ["policy." + key]


def test_receipt_must_commit_to_evidence(deployment):
    inp = deployment.inputs()
    inp.response["evidence"]["issued_at"] = "2030-01-15T12:00:01Z"  # evidence changed after signing
    assert statuses(run(inp))["receipt.signature"] == "FAIL"


def test_compose_checks(deployment):
    inp = deployment.inputs(app_compose_raw=deployment.app_compose + b"\n")
    st = statuses(run(inp))
    assert st["compose.app_compose_hash"] == "FAIL" and st["compose.docker_compose"] == "SKIP"

    inp = deployment.inputs(docker_compose_text=deployment.compose_text + "# edited\n")
    st = statuses(run(inp))
    assert st["compose.docker_compose"] == "FAIL" and st["compose.self_digest"] == "FAIL"

    inp = deployment.inputs(app_compose_raw=None, docker_compose_text=None)
    st = statuses(run(inp))
    assert {st[k] for k in st if k.startswith("compose.")} == {"SKIP"}


def with_compose(old: str, new: str) -> synth.Deployment:
    """A deployment that really runs an edited compose (its measurements follow the edit)."""
    template = synth.COMPOSE_TEMPLATE
    assert old in template, old
    return synth.Deployment().use_compose(*synth.finish_compose(template.replace(old, new, 1)))


def test_operator_settable_variables_must_equal_the_policy_list(deployment):
    inp = deployment.inputs()
    inp.policy["verifier"]["allowed_envs"] = synth.SEALED[:3]                 # compose uses one the policy does not list
    assert statuses(run(inp))["compose.unmeasured_inputs"] == "FAIL"
    inp = deployment.inputs()
    inp.policy["verifier"]["allowed_envs"] = synth.SEALED + ["UPSTREAM_URL"]  # policy lists one that is not used
    assert statuses(run(inp))["compose.unmeasured_inputs"] == "FAIL"
    inp = deployment.inputs()
    del inp.policy["verifier"]["allowed_envs"]
    assert statuses(run(inp))["compose.unmeasured_inputs"] == "SKIP"


def test_operator_supplied_key_material_is_flagged(fake_dcap):
    dep = with_compose("      ENCLAVE_KEY_DIR: /state/keys\n",
                       "      ENCLAVE_KEY_DIR: /state/keys\n      RECEIPT_SIGNING_SEED: ${HF_TOKEN}\n")
    result = run(dep.inputs(collateral_json=fake_dcap))
    st = statuses(result)
    assert st["compose.keys_in_enclave"] == "FAIL" and st["compose.app_compose_hash"] == "PASS" and result.verdict == "FAIL"


def test_keys_in_enclave_needs_a_proxy_build_that_refuses_operator_keys(deployment, fake_dcap):
    inp = deployment.inputs(collateral_json=fake_dcap)
    detail = next(c["detail"] for c in run(inp).checks if c["id"] == "compose.keys_in_enclave")
    assert "gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@" + synth.PROXY_DIGEST in detail
    inp.policy["verifier"]["enclave_key_proxy_digests"] = []
    assert statuses(run(inp))["compose.keys_in_enclave"] == "FAIL"
    inp = deployment.inputs(collateral_json=fake_dcap)
    del inp.policy["verifier"]["enclave_key_proxy_digests"]
    assert statuses(run(inp))["compose.keys_in_enclave"] == "FAIL"


def test_exposed_model_server_fails(fake_dcap):
    dep = with_compose("    networks:\n      inference: null\n    volumes:", "    network_mode: host\n    volumes:")
    st = statuses(run(dep.inputs(collateral_json=fake_dcap)))
    assert st["compose.inference_isolated"] == "FAIL" and st["compose.single_ingress"] == "FAIL"
    dep = with_compose("    name: dstack_inference\n    internal: true\n", "    name: dstack_inference\n")
    st = statuses(run(dep.inputs(collateral_json=fake_dcap)))
    assert st["compose.inference_isolated"] == "FAIL" and st["compose.single_ingress"] == "PASS"
    dep = with_compose("    network_mode: none\n", "    ports:\n    - '9000:9000'\n")
    st = statuses(run(dep.inputs(collateral_json=fake_dcap)))
    assert st["compose.inference_isolated"] == "PASS" and st["compose.single_ingress"] == "FAIL"


def test_unreadable_compose_fails_closed(fake_dcap):
    dep = with_compose("    cap_drop:\n    - ALL\n", "    cap_drop: &caps\n    - ALL\n")   # a YAML anchor
    st = statuses(run(dep.inputs(collateral_json=fake_dcap)))
    assert {st[k] for k in ("compose.images_pinned", "compose.unmeasured_inputs", "compose.keys_in_enclave",
                            "compose.inference_isolated", "compose.single_ingress")} == {"FAIL"}


def test_live_tls_key_must_be_the_attested_one(deployment):
    inp = deployment.inputs(live_spki="sha256:other", spki_seen=["sha256:other"])
    st = statuses(run(inp))
    assert st["tls.live_spki"] == "FAIL"
    inp = deployment.inputs()
    inp.spki_seen = inp.spki_seen + ["sha256:other"]  # one of several connections saw a different key
    assert statuses(run(inp))["tls.live_spki"] == "FAIL"


def test_hpke_endpoint_must_serve_attested_key(deployment):
    assert statuses(run(deployment.inputs(hpke_keys_body=b"\x00" * 35)))["keys.hpke_endpoint"] == "FAIL"


def ka_statuses(deployment, fake_dcap, key_attestation=None, **overrides):
    inp = deployment.inputs(collateral_json=fake_dcap, **overrides)
    if key_attestation is not None:
        inp.key_attestation = key_attestation
    return statuses(run(inp))


KEYATT = ("keyatt.report_data", "keyatt.quote", "keyatt.statement", "keyatt.keys_origin", "keyatt.keys_match", "keyatt.meter_key")


def test_key_attestation_passes_and_is_summarised(deployment, fake_dcap):
    result = run(deployment.inputs(collateral_json=fake_dcap))
    st = statuses(result)
    assert {st[k] for k in KEYATT} == {"PASS"} and st["statusz.consistent"] == "PASS"
    keys = result.summary["keys"]
    assert keys["keys_origin"] == "enclave-generated" and keys["meter_kid"] == deployment.meter_jwk["kid"]
    assert set(keys["key_statement"]) == {"type", "issued_at", "proxy_version", "keys_origin", "receipt_pubkey_jwk",
                                          "meter_pubkey_jwk", "ehbp_public_key", "ehbp_public_key_sha256", "tls_spki_sha256"}


def test_key_statement_altered_after_quoting_fails(deployment, fake_dcap):
    doc = deployment.key_attestation()
    doc["statement"] = doc["statement"].replace("enclave-generated", "enclave-generated ")
    st = ka_statuses(deployment, fake_dcap, doc)
    assert st["keyatt.report_data"] == "FAIL"
    assert {st[k] for k in KEYATT[1:]} == {"SKIP"}   # nothing is concluded from an unbound statement


def test_key_statement_must_be_the_served_bytes_in_canonical_form(deployment, fake_dcap):
    pretty = json.dumps(deployment.key_statement(), indent=1)            # quote commits to it, but it is not canonical
    assert ka_statuses(deployment, fake_dcap, deployment.key_attestation(statement=pretty))["keyatt.report_data"] == "FAIL"
    doc = deployment.key_attestation()
    for mutate in (lambda d: d.update(statement=json.loads(d["statement"])),   # an object instead of the string
                   lambda d: d.pop("quote"), lambda d: d.update(quote="zz")):
        broken = dict(doc)
        mutate(broken)
        assert ka_statuses(deployment, fake_dcap, broken)["keyatt.report_data"] == "FAIL"
    # report_data of a fresh attestation (SHA-256 || zeros) can never pass as a key attestation
    replayed = dict(doc, quote=deployment.response()["evidence"]["tdx_quote"])
    assert ka_statuses(deployment, fake_dcap, replayed)["keyatt.report_data"] == "FAIL"


def test_key_attestation_from_another_vm_fails(deployment, fake_dcap):
    other = synth.Deployment()
    other.platform = deployment.platform
    other.events = synth.make_event_log("77" * 32)
    other.rtmrs = eventlog.replay(other.events)
    st = ka_statuses(deployment, fake_dcap, other.key_attestation())
    assert st["keyatt.report_data"] == "PASS" and st["keyatt.quote"] == "FAIL" and st["keyatt.keys_match"] == "FAIL"


def test_key_attestation_quote_must_be_genuine(deployment, fake_dcap):
    forged = synth.Deployment()                       # same measurements and keys, but another "Intel" root
    doc = deployment.key_attestation()
    doc["quote"] = forged.platform.quote(bytes.fromhex(doc["quote"])[48 + 520:48 + 584], deployment.rtmrs).hex()
    st = ka_statuses(deployment, fake_dcap, doc)
    assert st["keyatt.report_data"] == "PASS" and st["keyatt.quote"] == "FAIL"

    doc = deployment.key_attestation()
    statement = doc["statement"]
    report_data = bytes.fromhex(doc["quote"])[48 + 520:48 + 584]
    doc["quote"] = deployment.platform.quote(report_data, deployment.rtmrs, debug=True).hex()
    assert ka_statuses(deployment, fake_dcap, doc)["keyatt.quote"] == "FAIL"                 # debug TD
    doc = dict(deployment.key_attestation(statement=statement), event_log=json.dumps(synth.make_event_log("66" * 32)))
    assert ka_statuses(deployment, fake_dcap, doc)["keyatt.quote"] == "FAIL"                 # event log of another compose

    st = ka_statuses(deployment, json.dumps({"status": "OutOfDate"}))
    assert st["keyatt.quote"] == "FAIL"
    st = statuses(run(deployment.inputs()))                                                  # no Intel collateral
    assert st["keyatt.quote"] == "SKIP"


def test_key_statement_content_is_checked(deployment, fake_dcap):
    def st(**overrides):
        return ka_statuses(deployment, fake_dcap, deployment.key_attestation(**overrides))

    for origin in ("operator-seed", "process-ephemeral", None):
        got = st(keys_origin=origin)
        assert got["keyatt.keys_origin"] == "FAIL" and got["keyatt.report_data"] == got["keyatt.quote"] == "PASS"
    assert st(type="adverserial-key-attestation/v2")["keyatt.statement"] == "FAIL"
    assert st(dev=True)["keyatt.statement"] == "FAIL"
    assert st(proxy_version="v9.9.9")["keyatt.statement"] == "FAIL"
    assert st(issued_at="2030-01-15T11:50:00Z")["keyatt.statement"] == "FAIL"     # ten minutes before the fresh attestation
    assert st(issued_at="2030-01-15T11:59:10Z")["keyatt.statement"] == "PASS"     # inside the proxy's 60 s cache
    assert st(issued_at="not a time")["keyatt.statement"] == "FAIL"


def test_key_statement_must_list_the_keys_in_use(deployment, fake_dcap):
    other = synth.Deployment()

    def st(**overrides):
        return ka_statuses(deployment, fake_dcap, deployment.key_attestation(**overrides))["keyatt.keys_match"]

    assert st(receipt_pubkey_jwk=other.receipt_jwk) == "FAIL"
    assert st(receipt_pubkey_jwk=dict(deployment.receipt_jwk, kid="someone-else")) == "FAIL"
    assert st(receipt_pubkey_jwk=dict(deployment.receipt_jwk, d="AAAA")) == "FAIL"          # a private member
    assert st(ehbp_public_key=synth.b64u(other.ehbp_pub)) == "FAIL"
    assert st(ehbp_public_key=None, ehbp_public_key_sha256=None) == "FAIL"
    assert st(ehbp_public_key_sha256="sha256:wrong") == "FAIL"
    assert st(tls_spki_sha256="sha256:other") == "FAIL"

    # the statement agrees with the evidence, but the live certificate is a different key
    inp = deployment.inputs(collateral_json=fake_dcap, live_spki="sha256:mitm", spki_seen=["sha256:mitm"])
    assert statuses(run(inp))["keyatt.keys_match"] == "FAIL"

    # policy pins
    inp = deployment.inputs(collateral_json=fake_dcap)
    inp.policy["receipt_keys"] = [deployment.receipt_jwk["kid"]]
    inp.policy["tls_spki_sha256"] = inp.response["evidence"]["tls_spki_sha256"]
    assert statuses(run(inp))["keyatt.keys_match"] == "PASS"
    inp.policy["receipt_keys"] = [other.receipt_jwk["kid"]]
    assert statuses(run(inp))["keyatt.keys_match"] == "FAIL"
    inp.policy["receipt_keys"] = [deployment.receipt_jwk["kid"]]
    inp.policy["tls_spki_sha256"] = "sha256:other"
    assert statuses(run(inp))["keyatt.keys_match"] == "FAIL"


def test_meter_jwks_must_be_the_attested_meter_key(deployment, fake_dcap):
    other = synth.Deployment()
    assert ka_statuses(deployment, fake_dcap, meter_jwks=other.meter_jwks())["keyatt.meter_key"] == "FAIL"
    assert ka_statuses(deployment, fake_dcap, meter_jwks={"keys": []})["keyatt.meter_key"] == "FAIL"
    both = {"keys": [deployment.meter_jwk, other.meter_jwk]}           # an extra, unattested key
    assert ka_statuses(deployment, fake_dcap, meter_jwks=both)["keyatt.meter_key"] == "FAIL"
    assert ka_statuses(deployment, fake_dcap, meter_jwks={"error": "response is not JSON"})["keyatt.meter_key"] == "FAIL"
    result = run(deployment.inputs(collateral_json=fake_dcap, meter_jwks=None))
    assert statuses(result)["keyatt.meter_key"] == "SKIP" and result.verdict == "INCOMPLETE"
    assert statuses(run(deployment.inputs(live=False, collateral_json=fake_dcap)))["keyatt.meter_key"] == "N/A"
    saved = deployment.inputs(live=False, collateral_json=fake_dcap, meter_jwks=deployment.meter_jwks())
    assert statuses(run(saved))["keyatt.meter_key"] == "PASS"
    for bad in (None, dict(deployment.meter_jwk, kid="x"), dict(deployment.meter_jwk, crv="P-256"), dict(deployment.meter_jwk, d="AA")):
        doc = deployment.key_attestation(meter_pubkey_jwk=bad)
        assert ka_statuses(deployment, fake_dcap, doc, meter_jwks={"keys": [bad]})["keyatt.meter_key"] == "FAIL"


def test_missing_key_attestation_leaves_the_verdict_incomplete(deployment, fake_dcap):
    result = run(deployment.inputs(collateral_json=fake_dcap, key_attestation=None))
    st = statuses(result)
    assert {st[k] for k in KEYATT} == {"SKIP"} and result.verdict == "INCOMPLETE"


def test_statusz_is_informational_but_must_not_contradict_the_attestation(deployment, fake_dcap):
    result = run(deployment.inputs(collateral_json=fake_dcap, statusz=None))
    assert statuses(result)["statusz.consistent"] == "N/A" and result.verdict == "PASS"      # absence changes nothing
    result = run(deployment.inputs(collateral_json=fake_dcap))
    assert result.summary["statusz"] == {"version": synth.PROXY_VERSION, "keys_origin": "enclave-generated",
                                         "receipt_kid": deployment.receipt_jwk["kid"],
                                         "ehbp_public_key_sha256": result.summary["keys"]["ehbp_public_key_sha256"]}
    for field, value in (("version", "v0.0.0-other"), ("keys_origin", "operator-seed"), ("receipt_kid", "other"),
                         ("ehbp_public_key_sha256", None)):
        sz = dict(deployment.statusz(), **{field: value})
        result = run(deployment.inputs(collateral_json=fake_dcap, statusz=sz))
        assert statuses(result)["statusz.consistent"] == "FAIL" and result.verdict == "FAIL", field


def test_gpu_checks(deployment):
    few = synth.Deployment(gpus=4)
    assert statuses(run(few.inputs()))["gpu.evidence"] == "FAIL"

    inp = deployment.inputs()
    inp.response["evidence"]["gpu_evidence_stale"] = True
    assert statuses(run(inp))["gpu.evidence"] == "FAIL"

    inp = deployment.inputs()
    _, other_keys = synth.make_gpu_bundle(8, deployment.at)
    inp.nras_jwks = other_keys  # same key id, different key: signature must not verify
    assert statuses(run(inp))["gpu.signatures"] == "FAIL"

    inp = deployment.inputs(nras_jwks={"keys": [dict(deployment.jwks["keys"][0], kid="rotated")]})
    assert statuses(run(inp))["gpu.signatures"] == "FAIL"          # live: unknown key is a failure
    inp = deployment.inputs(live=False, nras_jwks={"keys": [dict(deployment.jwks["keys"][0], kid="rotated")]})
    assert statuses(run(inp))["gpu.signatures"] == "SKIP"          # saved file: needs the recorded key set

    assert statuses(run(deployment.inputs(nras_jwks=None)))["gpu.signatures"] == "SKIP"


def test_malformed_evidence_never_crashes(deployment):
    for mutate in (lambda r: r.pop("evidence"), lambda r: r["evidence"].update(tdx_quote="zz"),
                   lambda r: r["evidence"].update(tdx_quote="00" * 700), lambda r: r["evidence"].update(tdx_event_log="[]"),
                   lambda r: r["evidence"].update(receipt_pubkey_jwk={"kty": "EC"}), lambda r: r["evidence"].update(gpu_evidence=None)):
        inp = deployment.inputs()
        mutate(inp.response)
        assert run(inp).verdict == "FAIL"
