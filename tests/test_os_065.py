"""dstack 0.6.x: manifest version "3", the compose-hash rule, and GPU attestation by the OS.

On 2026-11-24 the hosting provider moved the deployment from dstack-nvidia-0.5.15
to dstack-0.6.5. Three things changed for a verifier, and each is pinned here:

  * the measured manifest: `manifest_version` is the string "3", it carries
    `requirements.gpu_policy`, and `"init_script":[]` is part of the measured
    bytes (for version 2 it was not);
  * the event log: a `gpu-policy-hash` event inside the boot boundary, and a
    `gpu-attestation` event only when the OS attested the GPUs;
  * the provider set `"attest_gpu": false`. The verifier says so on every run
    as WARN `gpu.os_attestation`: not a failure, never silent.

It also covers the release that this overtook: published as pending, never
served, kept as published and marked superseded in the changelog.
"""
import hashlib
import json

import pytest

import chainlib
import prepare_release
import record
import synth
import validate_deployments
import verify
from avlib import checks, compose, eventlog
from conftest import ROOT
from synth import statuses
from test_pending_release import TAG, make_repo, pending_policy, recorder_files

DEPLOYMENTS = ROOT / "deployments"
V2_RELEASE, V2_HASH = "v0.1.0-rc.33", "275c6e538a381def20642459b5f5b37f5684d50b877604ee593c449ae51b1a1d"
V3_RELEASE, V3_HASH = "v0.1.0-rc.33-os-0.6.5", "9c78bf82dfad3a133838f2ac87406b3fe1c9d875d8a4d5fbe04e9f34d7d3b820"
OFF_HASH = "930188e08f58d0c555acff500a40be79c1f7e1d9ae23d26d901486cc9cc1a77d"
# Keys the Phala API view of a VM adds with null values; they are not in the measured bytes.
API_NULLS = ("bash_script", "default_gateway_domain", "key_provider", "key_provider_id", "port_policy", "storage_discard",
             "event_log_version", "snapshotter", "verity_volumes", "salt", "swap_size")


# ---- the compose-hash rule ---------------------------------------------------

def test_rule_keeps_empty_init_script_for_version_3_and_drops_it_for_version_2():
    base = {"runner": "docker-compose", "docker_compose_file": "services: {}\n", "bash_script": None, "init_script": [], "name": ""}
    v2 = compose.canonical_app_compose(dict(base, manifest_version=2))
    v3 = compose.canonical_app_compose(dict(base, manifest_version="3", requirements={"gpu_policy": {"attest_gpu": False}}))
    assert v2 == b'{"docker_compose_file":"services: {}\\n","manifest_version":2,"name":"","runner":"docker-compose"}'
    assert v3 == (b'{"docker_compose_file":"services: {}\\n","init_script":[],"manifest_version":"3","name":"",'
                  b'"requirements":{"gpu_policy":{"attest_gpu":false}},"runner":"docker-compose"}')
    # A non-empty init_script is content, in every version; null is never content.
    assert b'"init_script":["x"]' in compose.canonical_app_compose(dict(base, manifest_version=2, init_script=["x"]))
    assert b"bash_script" not in v2 + v3


@pytest.mark.parametrize("release, expected, version", [(V2_RELEASE, V2_HASH, 2), (V3_RELEASE, V3_HASH, "3")])
def test_published_manifests_are_the_measured_bytes_and_the_rule_rebuilds_them_from_the_api_view(release, expected, version):
    raw = (DEPLOYMENTS / release / "app-compose.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected                      # sha256sum of the file, nothing else
    app = json.loads(raw)
    assert app["manifest_version"] == version and app["name"] == ""          # "3" is a string; the empty name is in the bytes
    assert ("init_script" in app) == (version == "3")
    api_view = dict(app, init_script=[], **{k: None for k in API_NULLS})     # what `phala cvms get --json` shows
    assert compose.canonical_app_compose(api_view) == raw
    assert compose.app_compose_hash(raw) == (expected, expected)


def test_the_two_manifests_differ_only_in_what_the_provider_changed():
    old = json.loads((DEPLOYMENTS / V2_RELEASE / "app-compose.json").read_bytes())
    new = json.loads((DEPLOYMENTS / V3_RELEASE / "app-compose.json").read_bytes())
    assert {k for k in set(old) | set(new) if old.get(k) != new.get(k)} == {"manifest_version", "requirements", "init_script"}
    assert new["requirements"] == {"gpu_policy": {"attest_gpu": False}} and new["init_script"] == []
    assert (DEPLOYMENTS / V2_RELEASE / "docker-compose.yml").read_bytes() == (DEPLOYMENTS / V3_RELEASE / "docker-compose.yml").read_bytes()


def test_gpu_policy_hash_is_sha256_of_the_canonical_policy():
    assert compose.gpu_policy_hash({"attest_gpu": False}) == compose.GPU_ATTESTATION_OFF_HASH == OFF_HASH
    assert compose.gpu_policy_hash(compose.gpu_policy({})) == hashlib.sha256(b"{}").hexdigest()     # absent policy = {}
    assert compose.gpu_policy_hash({"rego": "x", "attest_gpu": True}) == hashlib.sha256(b'{"attest_gpu":true,"rego":"x"}').hexdigest()
    policy = json.loads((DEPLOYMENTS / V3_RELEASE / "policy.json").read_text())
    app = json.loads((DEPLOYMENTS / V3_RELEASE / "app-compose.json").read_bytes())
    assert policy["tdx"]["gpu_policy_hash"] == compose.gpu_policy_hash(compose.gpu_policy(app)) == OFF_HASH
    with pytest.raises(compose.ComposeViolation):
        compose.gpu_policy({"requirements": {"gpu_policy": "off"}})


# ---- the event log -----------------------------------------------------------

def test_event_order_of_dstack_065_is_accepted():
    events = synth.make_event_log("aa" * 32, OFF_HASH)
    assert [e["event"] for e in events if e["imr"] == 3] == [
        "system-preparing", "app-id", "compose-hash", "gpu-policy-hash", "instance-id", "boot-mr-done", "os-image-hash",
        "key-provider", "storage-fs", "storage-encrypted", "system-ready"]
    facts = eventlog.runtime_facts(events)
    assert facts["gpu-policy-hash"] == OFF_HASH and "gpu-attestation" not in facts


def test_gpu_events_must_be_unique_and_inside_the_boot_boundary():
    events = synth.make_event_log("aa" * 32, OFF_HASH)
    names = [e["event"] for e in events]
    with pytest.raises(eventlog.EventLogError, match="duplicate trusted event: gpu-policy-hash"):
        eventlog.runtime_facts(events + [synth.runtime_event("gpu-policy-hash", bytes(32))])
    late = [e for e in events if e["event"] != "gpu-policy-hash"]
    late.insert([e["event"] for e in late].index("boot-mr-done") + 1, events[names.index("gpu-policy-hash")])
    with pytest.raises(eventlog.EventLogError, match="gpu-policy-hash was recorded outside the trusted boot boundary"):
        eventlog.runtime_facts(late)
    # An application can extend RTMR3 after boot; it must not be able to claim the OS attested the GPUs.
    with pytest.raises(eventlog.EventLogError, match="gpu-attestation was recorded outside the trusted system boundary"):
        eventlog.runtime_facts(events + [synth.runtime_event("gpu-attestation", b"\x01" * 32)])


# ---- the verifier ------------------------------------------------------------

def run(dep, fake_dcap, **overrides):
    return checks.run(dep.inputs(collateral_json=fake_dcap, **overrides))


def test_attest_gpu_false_is_a_prominent_warning_not_a_failure(deployment, fake_dcap, capsys):
    result = run(deployment.use_os_065(), fake_dcap)
    st = statuses(result)
    assert st["gpu.os_attestation"] == "WARN" and st["policy.gpu_policy_hash"] == "PASS"
    assert [k for k, v in st.items() if v not in ("PASS", "N/A", "WARN")] == [], result.to_json()
    assert result.verdict == "PASS"                                                  # it does not fail the verdict by itself
    (warning,) = result.summary["warnings"]
    assert warning["id"] == "gpu.os_attestation"
    assert warning["detail"].startswith("GPU attestation by the OS is disabled by policy (attest_gpu=false)")
    assert "Nothing in the measured boot chain verifies the GPUs' protected mode" in warning["detail"]
    assert result.summary["gpu_os_attestation"] == "disabled-by-policy" and result.summary["gpu_policy_hash"] == OFF_HASH
    text = verify.render(result)
    assert "[WARN] gpu.os_attestation" in text
    assert "\nWARNING (gpu.os_attestation): GPU attestation by the OS is disabled by policy (attest_gpu=false)" in text
    assert "1 warning in live mode" in text
    assert text.splitlines()[-1].startswith("VERDICT: PASS") and text.splitlines()[-1].endswith("1 WARNING above: gpu.os_attestation)")


def test_a_pending_policy_with_the_warning_is_still_incomplete(deployment, fake_dcap):
    deployment.use_os_065()
    result = checks.run(deployment.inputs(collateral_json=fake_dcap, policy=pending_policy(deployment)))
    assert result.verdict == "INCOMPLETE" and statuses(result)["gpu.os_attestation"] == "WARN"
    assert "WARNING (gpu.os_attestation)" in verify.render(result)


def test_dstack_05_has_no_os_gpu_attestation_and_says_so(deployment, fake_dcap):
    result = run(deployment, fake_dcap)
    st = statuses(result)
    assert st["gpu.os_attestation"] == st["policy.gpu_policy_hash"] == "N/A" and result.verdict == "PASS"
    assert result.summary["gpu_os_attestation"] == "not-supported-by-os" and result.summary["warnings"] == []


def test_os_attested_gpus_pass(deployment, fake_dcap):
    result = run(deployment.use_os_065(gpu_policy={"attest_gpu": True}, gpu_attestation=b"\x05" * 32), fake_dcap)
    assert statuses(result)["gpu.os_attestation"] == "PASS" and result.verdict == "PASS"
    assert result.summary["gpu_os_attestation"] == "attested-at-boot" and result.summary["warnings"] == []
    # The default policy (an empty object) also requires attestation.
    assert statuses(run(synth.Deployment().use_os_065(gpu_policy={}, gpu_attestation=b"\x05" * 32), fake_dcap))["gpu.os_attestation"] == "PASS"


def test_contradictions_between_policy_and_event_log_fail(fake_dcap):
    required_but_absent = run(synth.Deployment().use_os_065(gpu_policy={"attest_gpu": True}), fake_dcap)
    assert statuses(required_but_absent)["gpu.os_attestation"] == "FAIL" and required_but_absent.verdict == "FAIL"
    disabled_but_present = run(synth.Deployment().use_os_065(gpu_attestation=b"\x05" * 32), fake_dcap)
    assert statuses(disabled_but_present)["gpu.os_attestation"] == "FAIL"

    dep = synth.Deployment().use_os_065()                                             # measured hash is not the manifest's policy
    dep.events = synth.make_event_log(dep.compose_hash, "77" * 32)
    dep.rtmrs = eventlog.replay(dep.events)
    dep.gpu_policy_hash = "77" * 32
    result = run(dep, fake_dcap)
    assert statuses(result)["gpu.os_attestation"] == "FAIL" and "is not SHA-256(JCS(requirements.gpu_policy))" in json.dumps(result.checks)

    dep = synth.Deployment().use_os_065()                                             # attestation event without a policy event
    dep.events = [e for e in synth.make_event_log(dep.compose_hash, OFF_HASH, b"\x05" * 32) if e["event"] != "gpu-policy-hash"]
    dep.rtmrs = eventlog.replay(dep.events)
    assert statuses(run(dep, fake_dcap))["gpu.os_attestation"] == "FAIL"


def test_the_policy_must_pin_the_measured_gpu_policy_hash(fake_dcap):
    unpinned = run(synth.Deployment().use_os_065(pin=False), fake_dcap)
    assert statuses(unpinned)["policy.gpu_policy_hash"] == "SKIP" and unpinned.verdict == "INCOMPLETE"
    dep = synth.Deployment().use_os_065()
    policy = dep.policy()
    policy["tdx"]["gpu_policy_hash"] = "00" * 32
    wrong = run(dep, fake_dcap, policy=policy)
    assert statuses(wrong)["policy.gpu_policy_hash"] == "FAIL" and wrong.verdict == "FAIL"
    dep = synth.Deployment()                                                          # pinned, but the OS measured none
    policy = dep.policy()
    policy["tdx"]["gpu_policy_hash"] = OFF_HASH
    assert statuses(run(dep, fake_dcap, policy=policy))["policy.gpu_policy_hash"] == "FAIL"


def test_without_the_manifest_the_known_opt_out_hash_still_warns(fake_dcap):
    result = run(synth.Deployment().use_os_065(), fake_dcap, app_compose_raw=None)
    assert statuses(result)["gpu.os_attestation"] == "WARN"
    other = run(synth.Deployment().use_os_065(gpu_policy={"attest_gpu": False, "allow_devtools": True}), fake_dcap, app_compose_raw=None)
    assert statuses(other)["gpu.os_attestation"] == "SKIP"                            # an unknown policy needs the manifest


def test_the_recorder_writes_the_warning_into_the_history(tmp_path, deployment, fake_dcap, monkeypatch, capsys):
    real_gather = verify.gather

    def gather(args):  # synthetic evidence is signed under a throwaway root; the command line cannot select one
        inp, raw = real_gather(args)
        inp.trust_root = deployment.platform.root
        return inp, raw

    monkeypatch.setattr(record.verifier, "gather", gather)
    deployment.use_os_065()
    root = make_repo(tmp_path, deployment, deployment.policy())
    assert record.main(["--root", str(root), "--at", "2030-01-15T12:00:00Z", *recorder_files(tmp_path, deployment, fake_dcap)]) == 0
    capsys.readouterr()
    (entry,) = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert entry["verdict"] == "PASS" and entry["warnings"] == ["gpu.os_attestation"]
    assert entry["gpu_os_attestation"] == "disabled-by-policy" and entry["gpu_policy_hash"] == OFF_HASH
    saved = json.loads((root / entry["files"]["verifier"]["path"]).read_text())
    assert saved["summary"]["warnings"][0]["id"] == "gpu.os_attestation"


# ---- the validator -----------------------------------------------------------

def errors(dep, policy):
    return " | ".join(validate_deployments.check_release(json.dumps(policy).encode(), dep.app_compose, dep.compose_text))


def test_a_version_3_release_must_pin_the_right_gpu_policy_hash(deployment):
    deployment.use_os_065()
    assert errors(deployment, deployment.policy()) == ""
    missing = deployment.policy()
    del missing["tdx"]["gpu_policy_hash"]
    assert "policy.tdx.gpu_policy_hash is missing" in errors(deployment, missing) and OFF_HASH in errors(deployment, missing)
    wrong = deployment.policy()
    wrong["tdx"]["gpu_policy_hash"] = compose.gpu_policy_hash({"attest_gpu": True})
    assert "the manifest's requirements.gpu_policy hashes to " + OFF_HASH in errors(deployment, wrong)
    v2 = synth.Deployment()
    policy = v2.policy()
    policy["tdx"]["gpu_policy_hash"] = OFF_HASH
    assert "is not one whose OS measures a GPU policy" in errors(v2, policy)


def test_published_bytes_must_be_in_the_measured_form(deployment):
    deployment.use_os_065()
    app = json.loads(deployment.app_compose)
    pretty = json.dumps(app, indent=1).encode()
    deployment.use_compose(deployment.compose_text, pretty)
    assert "is not in the measured form" in errors(deployment, dict(deployment.policy(), tdx=dict(
        deployment.policy()["tdx"], gpu_policy_hash=OFF_HASH)))


# ---- a pending release that never served ---------------------------------------

def supersede(root, release=TAG):
    path = root / "deployments" / "CHANGELOG.md"
    path.write_text(path.read_text().replace("## %s\n" % release, "## %s\n- Status: %s (2030-01-15): the provider replaced the OS image.\n"
                                             % (release, validate_deployments.SUPERSEDED_STATUS)))


def test_a_superseded_release_is_kept_reported_and_never_completed(tmp_path, deployment, capsys):
    old = synth.Deployment()
    root = make_repo(tmp_path, old, pending_policy(old))
    deployments = root / "deployments"
    assert validate_deployments.main([str(deployments), "--fail-on-pending"]) == 1          # still pending: counted
    supersede(root)
    assert validate_deployments.main([str(deployments)]) == 1                                # CURRENT may not name it
    assert "point it at the release that replaced it" in capsys.readouterr().out
    deployment.use_os_065()
    new = deployments / "v0.0.2-test"
    new.mkdir()
    (new / "policy.json").write_text(json.dumps(deployment.policy()))
    (new / "app-compose.json").write_bytes(deployment.app_compose)
    (new / "docker-compose.yml").write_text(deployment.compose_text)
    (deployments / "CURRENT").write_text("v0.0.2-test\n")
    (deployments / "CHANGELOG.md").write_text((deployments / "CHANGELOG.md").read_text() + "\n## v0.0.2-test\n- test\n")
    assert validate_deployments.main([str(deployments), "--fail-on-pending"]) == 0          # the superseded one no longer counts
    out = capsys.readouterr().out
    assert "[SUPERSEDED] %s" % TAG in out and "[VALID] v0.0.2-test" in out
    assert validate_deployments.load_pending(deployments) == {}                              # never offered to the recorder
    assert TAG not in validate_deployments.load_measurements(deployments)

    (tmp_path / "cvm.json").write_text(json.dumps({"app_id": synth.APP_ID, "compose_hash": old.compose_hash,
                                                   "compose_file": json.loads(old.app_compose)}))
    (tmp_path / "final.json").write_text(json.dumps(old.policy()))
    assert prepare_release.main([str(tmp_path / "cvm.json"), str(tmp_path / "final.json"), TAG, "--deployments", str(deployments),
                                 "--complete"]) == 1
    assert "never completed" in capsys.readouterr().err
    assert validate_deployments.is_pending(json.loads((deployments / TAG / "policy.json").read_text()))


def test_a_release_with_a_final_policy_cannot_be_called_superseded(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment, deployment.policy())
    supersede(root)
    assert validate_deployments.main([str(root / "deployments")]) == 1
    assert "only a release that was never verified can be superseded" in capsys.readouterr().out


def test_the_first_published_release_stays_superseded():
    """rc.33 on dstack-nvidia-0.5.15 never served: superseded for good, kept as published, never CURRENT again."""
    changelog = validate_deployments.changelog_text(DEPLOYMENTS)
    assert validate_deployments.is_superseded(changelog, V2_RELEASE) and not validate_deployments.is_superseded(changelog, V3_RELEASE)
    assert validate_deployments.read_current(DEPLOYMENTS)[0] != V2_RELEASE
    old = json.loads((DEPLOYMENTS / V2_RELEASE / "policy.json").read_text())
    assert validate_deployments.is_pending(old) and "mrtd" not in old["tdx"]                 # kept as published, never completed
    assert validate_deployments.main([str(DEPLOYMENTS)]) == 0
