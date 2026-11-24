"""A release published before its first live attestation: the `pending` state.

Pending relaxes exactly one thing, the presence of values that only a live
attestation can supply. These tests pin down that nothing else is relaxed,
that the verifier never says PASS against a pending policy, that the recorder
records the waiting period honestly, and that completing the policy is the
only change a published release accepts.
"""
import copy
import json
import shutil
import subprocess

import pytest

import chainlib
import prepare_release
import record
import recorder_issue
import synth
import validate_deployments
import verify
from avlib import checks, compose
from conftest import PLACEHOLDER_DEPLOYMENTS, ROOT
from synth import statuses

TAG = "v0.0.1-test"
REASON = "measurements, TLS pin and receipt key pending first live attestation"
MISSING = ["tdx.mrtd", "tdx.rtmr0", "tdx.rtmr1", "tdx.rtmr2", "tls_spki_sha256", "receipt_keys"]
FAKE = "Zz9" * 14  # shaped like a credential, assembled at run time


def pending_policy(dep: synth.Deployment, missing=MISSING, **pending) -> dict:
    policy = dep.policy()
    for name in missing:
        holder, key = (policy["tdx"], name[4:]) if name.startswith("tdx.") else (policy, name)
        holder.pop(key, None)
    policy.update(status="pending", pending=dict({"reason": REASON, "missing": list(missing)}, **pending))
    return policy


def release_errors(dep: synth.Deployment, policy: dict) -> str:
    return " | ".join(validate_deployments.check_release(json.dumps(policy).encode(), dep.app_compose, dep.compose_text))


def make_repo(tmp_path, dep: synth.Deployment, policy: dict, release=TAG):
    root = tmp_path / "repo"
    d = root / "deployments" / release
    d.mkdir(parents=True)
    (d / "policy.json").write_text(json.dumps(policy, indent=2))
    (d / "app-compose.json").write_bytes(dep.app_compose)
    (d / "docker-compose.yml").write_text(dep.compose_text)
    (root / "deployments" / "CURRENT").write_text(validate_deployments.current_text(release, policy))
    (root / "deployments" / "CHANGELOG.md").write_text("# Changelog\n\n## %s\n- test\n" % release)
    (root / "history").mkdir()
    return root


# ---- the validator --------------------------------------------------------

def test_pending_release_is_valid_and_reported_as_pending(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment, pending_policy(deployment))
    assert validate_deployments.main([str(root / "deployments")]) == 0
    out = capsys.readouterr().out
    assert "[PENDING] %s: %s" % (TAG, REASON) in out and out.strip().endswith("OK")
    assert validate_deployments.main([str(root / "deployments"), "--fail-on-pending"]) == 1
    assert validate_deployments.load_measurements(root / "deployments") == {}          # nothing to match measurements against
    assert validate_deployments.load_pending(root / "deployments") == {
        TAG: {"app_id": synth.APP_ID, "compose_hash": deployment.compose_hash, "os_image_hash": synth.OS_IMAGE_HASH}}


def test_pending_does_not_relax_the_secret_scan_or_any_hash_or_compose_check(deployment):
    assert release_errors(deployment, pending_policy(deployment)) == ""

    # a literal credential in the policy, the manifest or the compose
    assert "billing_api_token" in release_errors(deployment, dict(pending_policy(deployment), billing_api_token=FAKE))
    leaky = synth.Deployment().use_compose(*synth.finish_compose(
        synth.COMPOSE_TEMPLATE.replace("      MODEL_REVISION:", "      GANDI_PAT: %s\n      MODEL_REVISION:" % FAKE)))
    assert "GANDI_PAT" in release_errors(leaky, pending_policy(leaky))

    # the compose hash, the compose text and the COMPOSE_DIGEST
    wrong = pending_policy(deployment)
    wrong["tdx"]["compose_hash"] = "00" * 32
    assert "SHA-256(app-compose.json)" in release_errors(deployment, wrong)
    assert "deployment_configuration_digest" in release_errors(
        deployment, dict(pending_policy(deployment), deployment_configuration_digest="sha256:" + "00" * 32))
    edited = " | ".join(validate_deployments.check_release(json.dumps(pending_policy(deployment)).encode(), deployment.app_compose,
                                                           deployment.compose_text + "# edit\n"))
    assert "differs from docker_compose_file" in edited and "recomputes" in edited

    # every static compose check
    exposed = synth.Deployment().use_compose(*synth.finish_compose(
        synth.COMPOSE_TEMPLATE.replace("    name: dstack_inference\n    internal: true\n", "    name: dstack_inference\n")))
    assert "not declared internal" in release_errors(exposed, pending_policy(exposed))
    policy = pending_policy(deployment)
    policy["verifier"]["allowed_envs"] = synth.SEALED[:2]
    assert "operator-supplied variables differ" in release_errors(deployment, policy)
    policy = pending_policy(deployment)
    policy["verifier"]["enclave_key_proxy_digests"] = []
    assert "refuses operator-supplied keys" in release_errors(deployment, policy)
    policy = pending_policy(deployment)
    policy["proxy_image_digest"] = "sha256:" + "00" * 32
    assert "is not an image in the compose" in release_errors(deployment, policy)


def test_pending_marker_must_be_exact(deployment):
    # the identity of the release is known at rollout and is never optional
    for key in ("app_id", "compose_hash", "os_image_hash"):
        policy = pending_policy(deployment)
        del policy["tdx"][key]
        assert "policy.tdx.%s must be" % key in release_errors(deployment, policy)

    # "missing" names exactly what is absent: no more, no less, nothing else
    policy = pending_policy(deployment)
    policy["tdx"]["mrtd"] = "11" * 48
    assert "lists tdx.mrtd, but the policy has a value" in release_errors(deployment, policy)
    policy = pending_policy(deployment)
    policy["pending"]["missing"].remove("tdx.rtmr2")
    assert "policy.tdx.rtmr2 is absent but not listed" in release_errors(deployment, policy)
    policy = pending_policy(deployment)
    policy["tls_spki_sha256"] = "sha256:abc"
    assert "lists tls_spki_sha256, but the policy has a value" in release_errors(deployment, policy)
    for bad in ([], ["tdx.compose_hash"], ["tdx.mrtd", "tdx.mrtd"], "tdx.mrtd"):
        policy = pending_policy(deployment)
        policy["pending"]["missing"] = bad
        assert "policy.pending.missing must be a non-empty list" in release_errors(deployment, policy)

    # a value that is present must still be well formed
    policy = pending_policy(deployment, missing=["tdx.mrtd", "tdx.rtmr0", "tdx.rtmr1"])
    policy["tdx"]["rtmr2"] = "xyz"
    assert "policy.tdx.rtmr2 must be 96 lowercase hex" in release_errors(deployment, policy)

    # a reason is required, and half a marker is not a final policy
    policy = pending_policy(deployment)
    policy["pending"]["reason"] = " "
    assert "policy.pending.reason" in release_errors(deployment, policy)
    for half in ({"status": "pending"}, {"pending": {"reason": REASON, "missing": MISSING}}):
        policy = dict(pending_policy(deployment))
        policy.pop("status"), policy.pop("pending")
        policy.update(half)
        assert validate_deployments.is_pending(policy) and "needs both" in release_errors(deployment, policy)

    # a final policy with a measurement missing is an error, as before
    policy = deployment.policy()
    del policy["tdx"]["mrtd"]
    assert "policy.tdx.mrtd must be" in release_errors(deployment, policy)


def test_current_must_say_that_a_pending_release_is_not_verified(tmp_path, deployment, capsys):
    policy = pending_policy(deployment, detail="The service is not answering yet. " * 6)
    root = make_repo(tmp_path, deployment, policy)
    current = root / "deployments" / "CURRENT"
    lines = current.read_text().splitlines()
    assert lines[0] == TAG and lines[1] == "# Status: ROLLED OUT, NOT YET VERIFIED LIVE" and REASON in lines[2]
    assert all(line.startswith("#") and len(line) <= 79 for line in lines[3:]) and "not answering yet" in lines[3]
    assert validate_deployments.read_current(root / "deployments")[0] == TAG
    assert validate_deployments.main([str(root / "deployments")]) == 0

    current.write_text(TAG + "\n")                                   # pending, but CURRENT does not say so
    assert validate_deployments.main([str(root / "deployments")]) == 1
    assert "must say so" in capsys.readouterr().out
    current.write_text(TAG + "\nnot a comment\n")
    assert validate_deployments.main([str(root / "deployments")]) == 1
    assert "must be a comment" in capsys.readouterr().out

    final = make_repo(tmp_path / "final", deployment, deployment.policy())
    (final / "deployments" / "CURRENT").write_text(validate_deployments.current_text(TAG, policy))   # stale status line
    assert validate_deployments.main([str(final / "deployments")]) == 1
    assert "is final" in capsys.readouterr().out


# ---- the verifier ---------------------------------------------------------

def test_verifier_never_passes_against_a_pending_policy(deployment, fake_dcap):
    assert checks.run(deployment.inputs(collateral_json=fake_dcap)).verdict == "PASS"      # the same evidence, final policy

    inp = deployment.inputs(collateral_json=fake_dcap)
    inp.policy = pending_policy(deployment)
    result = checks.run(inp)
    st = statuses(result)
    assert result.verdict == "INCOMPLETE" and result.checks[0]["id"] == "policy.not_pending"
    assert st["policy.not_pending"] == "SKIP" and REASON in result.checks[0]["detail"] and "tdx.mrtd" in result.checks[0]["detail"]
    assert st["policy.mrtd"] == st["policy.rtmr0"] == "SKIP"
    # what is known is still enforced
    assert st["policy.compose_hash"] == st["policy.app_id"] == st["policy.os_image_hash"] == st["compose.keys_in_enclave"] == "PASS"
    assert "the policy for this release is pending" in verify.render(result) and "VERDICT: INCOMPLETE" in verify.render(result)

    # even a policy with every value present cannot pass while either marker is there
    for marker in ({"status": "pending"}, {"pending": {"reason": REASON, "missing": []}}, {"pending": None}):
        inp = deployment.inputs(collateral_json=fake_dcap)
        inp.policy.update(marker)
        result = checks.run(inp)
        assert statuses(result)["policy.not_pending"] == "SKIP" and result.verdict == "INCOMPLETE", marker
        assert [c["id"] for c in result.checks if c["status"] == "SKIP"] == ["policy.not_pending"], marker

    # a pending policy does not hide a failure
    inp = deployment.inputs(collateral_json=fake_dcap)
    inp.policy = pending_policy(deployment)
    inp.policy["tdx"]["compose_hash"] = "00" * 32
    result = checks.run(inp)
    assert result.verdict == "FAIL" and statuses(result)["policy.compose_hash"] == "FAIL"


def test_verifier_cli_names_the_pending_policy_when_the_endpoint_is_down(tmp_path, deployment, monkeypatch, capsys):
    from avlib import fetch
    root = make_repo(tmp_path, deployment, pending_policy(deployment))

    class Down:
        def __init__(self, url):
            raise fetch.FetchError("cannot connect to %s: connection refused" % url)

    monkeypatch.setattr(verify.fetch, "Endpoint", Down)
    code = verify.main(["https://api.example.test", "--offline", "--deployment", str(root / "deployments" / TAG)])
    err = capsys.readouterr().err
    assert code == 3 and "connection refused" in err and "policy for this release is pending" in err and REASON in err


# ---- the published release ------------------------------------------------

def test_the_published_current_release_is_consistent():
    """Whatever deployments/ holds today, pending or final, must validate; pending must be said in three places."""
    deployments = ROOT / "deployments"
    assert validate_deployments.main([str(deployments)]) == 0
    name, comments = validate_deployments.read_current(deployments)
    policy = json.loads((deployments / name / "policy.json").read_text())
    raw = (deployments / name / "app-compose.json").read_bytes()
    assert compose.sha256_hex(raw) == policy["tdx"]["compose_hash"] == compose.app_compose_hash(raw)[1]
    assert not (deployments / "PENDING").exists()
    changelog = (deployments / "CHANGELOG.md").read_text()
    section = changelog.split("## %s\n" % name, 1)[1].split("\n## ", 1)[0]
    if validate_deployments.is_pending(policy):
        assert validate_deployments.NOT_VERIFIED in section and any(validate_deployments.NOT_VERIFIED in c for c in comments)
        assert (ROOT / "history" / "attestations.jsonl").read_text().count('"verdict":"PASS"') == 0
    else:
        assert validate_deployments.NOT_VERIFIED not in section


# ---- the recorder ---------------------------------------------------------

def test_recorder_records_unreachable_while_pending(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment, pending_policy(deployment))
    for minute in ("00", "30"):
        code = record.main(["--root", str(root), "--file", str(tmp_path / "nothing-here.json"), "--at", "2030-01-15T12:%s:00Z" % minute,
                            "--offline"])
        assert code == record.EXIT_UNREACHABLE
    capsys.readouterr()
    history = root / "history" / "attestations.jsonl"
    assert chainlib.validate(history, root)[0] == 2
    for entry in (json.loads(line) for line in chainlib.read_lines(history)):
        assert entry["verdict"] == "UNREACHABLE" and entry["policy_state"] == "pending" and entry["expected_deployment"] == TAG
        assert "files" not in entry and entry["error"]


def recorder_files(tmp_path, dep, fake_dcap):
    docs = {"evidence": dep.response(), "key-attestation": dep.key_attestation(), "meter-jwks": dep.meter_jwks(),
            "statusz": dep.statusz(), "nras-jwks": dep.jwks}
    for name, doc in docs.items():
        (tmp_path / (name + ".json")).write_text(json.dumps(doc))
    (tmp_path / "collateral.json").write_text(fake_dcap)
    return ["--file", str(tmp_path / "evidence.json"), "--collateral", str(tmp_path / "collateral.json"),
            "--nras-jwks", str(tmp_path / "nras-jwks.json"), "--key-attestation-file", str(tmp_path / "key-attestation.json"),
            "--meter-jwks-file", str(tmp_path / "meter-jwks.json"), "--statusz-file", str(tmp_path / "statusz.json"), "--offline"]


def test_recorder_goes_from_pending_to_pass_when_the_policy_is_completed(tmp_path, deployment, fake_dcap, monkeypatch, capsys):
    """The workflow needs no change at completion: the same command starts to return 0."""
    real_gather = verify.gather

    def gather(args):  # synthetic evidence is signed under a throwaway root; the command line cannot select one
        inp, raw = real_gather(args)
        inp.trust_root = deployment.platform.root
        return inp, raw

    monkeypatch.setattr(record.verifier, "gather", gather)
    root = make_repo(tmp_path, deployment, pending_policy(deployment))
    files = recorder_files(tmp_path, deployment, fake_dcap)

    assert record.main(["--root", str(root), "--at", "2030-01-15T12:00:00Z", *files]) == record.EXIT_PENDING
    policy_file = root / "deployments" / TAG / "policy.json"
    policy_file.write_text(json.dumps(deployment.policy(), indent=2))                 # the policy is completed
    assert record.main(["--root", str(root), "--at", "2030-01-15T12:30:00Z", *files]) == 0
    capsys.readouterr()
    first, second = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert first["verdict"] == "INCOMPLETE" and first["skipped"] == ["policy.not_pending", "policy.mrtd", "policy.rtmr0",
                                                                       "policy.rtmr1", "policy.rtmr2"]
    assert first["policy_state"] == "pending" and first["deployment"] is None and first["pending_deployment"] == TAG
    assert first["failed"] == [] and first["measurements"]["mrtd"] == "11" * 48     # what was observed is on record
    assert second["verdict"] == "PASS" and second["policy_state"] == "final" and second["deployment"] == TAG
    assert "pending_deployment" not in second and second["skipped"] == []


def test_recorder_does_not_call_a_different_app_pending(tmp_path, deployment, fake_dcap, monkeypatch, capsys):
    real_gather = verify.gather

    def gather(args):
        inp, raw = real_gather(args)
        inp.trust_root = deployment.platform.root
        return inp, raw

    monkeypatch.setattr(record.verifier, "gather", gather)
    policy = pending_policy(deployment)
    policy["tdx"]["os_image_hash"] = "ee" * 32          # the endpoint runs another OS image than the pending release names
    root = make_repo(tmp_path, deployment, policy)
    assert record.main(["--root", str(root), "--at", "2030-01-15T12:00:00Z", *recorder_files(tmp_path, deployment, fake_dcap)]) == 1
    capsys.readouterr()
    (entry,) = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert entry["verdict"] == "FAIL" and entry["failed"] == ["policy.os_image_hash"] and "pending_deployment" not in entry


# ---- publishing and completing --------------------------------------------

def snapshot(dep: synth.Deployment) -> dict:
    app = json.loads(dep.app_compose)
    return {"app_id": synth.APP_ID, "compose_hash": dep.compose_hash, "os": {"os_image_hash": synth.OS_IMAGE_HASH},
            "docker_compose_hash": compose.sha256_hex(dep.compose_text.encode()), "compose_file": dict(app, init_script=[])}


def prepare(tmp_path, deployments, dep, policy, *extra):
    (tmp_path / "cvm.json").write_text(json.dumps(snapshot(dep)))
    (tmp_path / "policy.json").write_text(json.dumps(policy, indent=2))
    return prepare_release.main([str(tmp_path / "cvm.json"), str(tmp_path / "policy.json"), TAG, "--deployments", str(deployments), *extra])


@pytest.fixture
def repo(tmp_path):
    deployments = tmp_path / "deployments"
    shutil.copytree(PLACEHOLDER_DEPLOYMENTS, deployments)
    return deployments


def test_publish_pending_then_complete(tmp_path, repo, deployment, capsys):
    pending = pending_policy(deployment, detail="One GPU does not initialise.")
    assert prepare(tmp_path, repo, deployment, pending) == 1                       # pending must be asked for explicitly
    assert "pass --pending" in capsys.readouterr().err and not (repo / TAG).exists()
    assert prepare(tmp_path, repo, deployment, deployment.policy(), "--pending") == 1
    assert "not marked pending" in capsys.readouterr().err and not (repo / TAG).exists()

    assert prepare(tmp_path, repo, deployment, pending, "--pending", "--retire-placeholder", "--rolled-out", "2030-01-15",
                   "--changes", "test", "--os-image", "test-os-1.0") == 0
    assert "PENDING" in capsys.readouterr().out
    changelog = (repo / "CHANGELOG.md").read_text()
    assert "## %s\n- Status: ROLLED OUT, NOT YET VERIFIED LIVE. The policy is pending: %s\n" % (TAG, REASON) in changelog
    assert "- MRTD, RTMR0-2: pending first live attestation\n" in changelog and "- OS image: test-os-1.0, os_image_hash" in changelog
    assert "- First history entry under this release: none yet, pending first live attestation\n" in changelog
    assert (repo / "CURRENT").read_text().splitlines()[:2] == [TAG, "# Status: ROLLED OUT, NOT YET VERIFIED LIVE"]
    assert "One GPU does not initialise." in (repo / "CURRENT").read_text()
    assert validate_deployments.main([str(repo)]) == 0 and "[PENDING]" in capsys.readouterr().out
    before = {p.name: p.read_bytes() for p in (repo / TAG).iterdir()}

    # completion refuses: a policy that is still pending, a changed known value, a different VM
    final = deployment.policy()
    assert prepare(tmp_path, repo, deployment, pending, "--complete") == 1
    assert "still marked pending" in capsys.readouterr().err
    changed = copy.deepcopy(final)
    changed["verifier"]["accepted_tcb_status"] = ["UpToDate", "OutOfDate"]
    assert prepare(tmp_path, repo, deployment, changed, "--complete") == 1
    assert "policy.verifier.accepted_tcb_status was published as" in capsys.readouterr().err
    dropped = {k: v for k, v in final.items() if k != "proxy_version"}
    assert prepare(tmp_path, repo, deployment, dropped, "--complete") == 1
    assert "policy.proxy_version was published and is now missing" in capsys.readouterr().err
    other = synth.Deployment().use_compose(*synth.finish_compose(synth.COMPOSE_TEMPLATE + "# another deployment\n"))
    assert prepare(tmp_path, repo, other, other.policy(), "--complete") == 1
    assert "does not reproduce the published app-compose.json" in capsys.readouterr().err
    bad = copy.deepcopy(final)
    bad["tdx"]["mrtd"] = "xyz"
    assert prepare(tmp_path, repo, deployment, bad, "--complete") == 1
    assert "policy.tdx.mrtd must be" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in (repo / TAG).iterdir()} == before      # every refusal wrote nothing
    assert prepare(tmp_path, repo, deployment, final, "--complete", "--dry-run") == 0
    assert {p.name: p.read_bytes() for p in (repo / TAG).iterdir()} == before
    capsys.readouterr()

    assert prepare(tmp_path, repo, deployment, final, "--complete", "--completed-on", "2030-01-16 09:00 UTC") == 0
    after = {p.name: p.read_bytes() for p in (repo / TAG).iterdir()}
    assert sorted(after) == sorted(before) and after["policy.json"] == (tmp_path / "policy.json").read_bytes()
    assert after["app-compose.json"] == before["app-compose.json"] and after["docker-compose.yml"] == before["docker-compose.yml"]
    assert (repo / "CURRENT").read_text() == TAG + "\n"
    changelog = (repo / "CHANGELOG.md").read_text()
    assert "- Status: policy completed 2030-01-16 09:00 UTC from the first live attestation" in changelog
    assert "NOT YET VERIFIED" not in changelog and "- MRTD, RTMR0-2: see policy.json\n" in changelog
    assert "- First history entry under this release: TO BE FILLED IN\n" in changelog and "pending" not in changelog.split("## " + TAG)[1].split("- Status:")[1].split("\n", 1)[1]
    capsys.readouterr()
    assert validate_deployments.main([str(repo), "--fail-on-pending"]) == 0

    # a completed release is immutable again
    assert prepare(tmp_path, repo, deployment, final, "--complete") == 1
    assert "is not pending; published releases are never rewritten" in capsys.readouterr().err
    assert prepare(tmp_path, repo, deployment, final) == 1
    assert "already exists" in capsys.readouterr().err


def git(root, *args):
    done = subprocess.run(["git", "-C", str(root), "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                           "-c", "commit.gpgsign=false", *args], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_only_completing_a_pending_policy_may_change_a_published_release(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment, pending_policy(deployment))
    deployments, policy_file = root / "deployments", root / "deployments" / TAG / "policy.json"
    git(root, "init", "-q", "-b", "main")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "pending release")

    def check():
        code = validate_deployments.main([str(deployments), "--immutable-since", "HEAD"])
        return code, capsys.readouterr().out

    assert check()[0] == 0
    # completing: allowed. CURRENT and the changelog may change with it.
    policy_file.write_text(json.dumps(deployment.policy(), indent=2))
    (deployments / "CURRENT").write_text(TAG + "\n")
    assert check()[0] == 0
    # completing while changing a published value: refused
    policy = deployment.policy()
    policy["verifier"]["enclave_key_proxy_digests"].append("sha256:" + "77" * 32)
    policy_file.write_text(json.dumps(policy, indent=2))
    code, out = check()
    assert code == 1 and "policy.verifier.enclave_key_proxy_digests was published as" in out
    policy_file.write_text(json.dumps(deployment.policy(), indent=2))
    # touching the compose or the manifest: refused, pending or not
    (deployments / TAG / "docker-compose.yml").write_text(deployment.compose_text + "# edit\n")
    code, out = check()
    assert code == 1 and "%s/docker-compose.yml: a file of a published release was modified" % TAG in out
    (deployments / TAG / "docker-compose.yml").write_text(deployment.compose_text)
    assert check()[0] == 0

    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "complete the policy")
    # a final policy is immutable: not even an added pin
    policy_file.write_text(json.dumps(dict(deployment.policy(), tls_spki_sha256="sha256:abc"), indent=2))
    code, out = check()
    assert code == 1 and "%s/policy.json: a file of a published release was modified" % TAG in out
    git(root, "checkout", "-q", "--", ".")
    # a new release next to it: allowed; deleting the old one: refused
    shutil.copytree(deployments / TAG, deployments / "v0.0.2-test")
    (deployments / "CHANGELOG.md").write_text("# Changelog\n\n## v0.0.2-test\n- test\n\n## %s\n- test\n" % TAG)
    git(root, "add", "-A")
    assert check()[0] == 0
    shutil.rmtree(deployments / TAG)
    code, out = check()
    assert code == 1 and "was deleted" in out


# ---- one issue, not one every 30 minutes ----------------------------------

def entry(seq, verdict, **more):
    return dict({"seq": seq, "timestamp": "2030-01-15T12:%02d:00Z" % (seq % 60), "verdict": verdict}, **more)


def replay(runs):
    """Feed a sequence of (exit code, entry) through the planner the way the workflow does, with one fake issue tracker."""
    issue, log = None, []
    for code, e in runs:
        actions = recorder_issue.plan(issue, code, e, "https://example.invalid/run")
        for a in actions:
            if a["do"] == "create":
                assert issue is None
                issue = {"number": 1, "title": a["title"], "body": a["body"]}
            elif a["do"] == "edit":
                issue.update(title=a["title"], body=a["body"])
            elif a["do"] == "close":
                issue = None
        log.append([a["do"] for a in actions])
    return issue, log


def test_a_long_outage_is_one_issue_with_no_comments():
    runs = [(5, entry(i, "UNREACHABLE", error="connection refused")) for i in range(48)]       # one day
    issue, log = replay(runs)
    assert log[0] == ["create"] and all(step == ["edit"] for step in log[1:])                   # never a comment, never a 2nd issue
    state = recorder_issue.read_state(issue["body"])
    assert state == {"kind": "unreachable", "since": "2030-01-15T12:00:00Z", "since_seq": 0, "last": "2030-01-15T12:47:00Z",
                     "last_seq": 47, "runs": 48}
    assert issue["title"] == "Attestation recorder: Endpoint unreachable" and "| Consecutive runs | 48 |" in issue["body"]


def test_from_unreachable_through_pending_to_pass():
    runs = ([(5, entry(i, "UNREACHABLE")) for i in range(3)]
            + [(6, entry(i, "INCOMPLETE", policy_state="pending")) for i in range(3, 6)]
            + [(0, entry(6, "PASS")), (0, entry(7, "PASS"))])
    issue, log = replay(runs)
    assert log == [["create"], ["edit"], ["edit"], ["edit", "comment"], ["edit"], ["edit"], ["close"], []]
    assert issue is None                                                                        # closed by itself, nothing reopened


def test_a_failure_is_not_closed_by_a_later_pass():
    issue, log = replay([(1, entry(0, "FAIL", failed=["policy.compose_hash"])), (0, entry(1, "PASS")), (0, entry(2, "PASS")),
                         (5, entry(3, "UNREACHABLE"))])
    assert log == [["create"], ["edit", "comment"], [], ["edit", "comment"]]
    assert issue is not None and recorder_issue.read_state(issue["body"])["kind"] == "unreachable"


def test_issue_text_is_sanitised_and_unknown_codes_are_errors():
    (action,) = recorder_issue.plan(None, 5, entry(0, "UNREACHABLE", error="```\n@everyone look `here`"), "u")
    assert "@everyone" not in action["body"] and action["body"].count("```") == 2
    for code in ("", None, "workflow", 3, 7):
        (action,) = recorder_issue.plan(None, code, None, "u")
        assert action["do"] == "create" and "Recorder or workflow error" in action["title"]
    assert recorder_issue.plan(None, 0, entry(0, "PASS")) == [] and recorder_issue.plan(None, "0", entry(0, "PASS")) == []
    # an issue somebody opened by hand under the label is adopted, not duplicated
    manual = {"number": 9, "title": "manual", "body": "something is off"}
    assert [a["do"] for a in recorder_issue.plan(manual, 5, entry(0, "UNREACHABLE"), "u")] == ["edit", "comment"]


def test_recorder_issue_dry_run_prints_the_plan(tmp_path, capsys):
    (tmp_path / "record.json").write_text(json.dumps({"exit": 5, "entry": entry(4, "UNREACHABLE", error="timed out")}))
    (tmp_path / "issue.json").write_text("null")
    assert recorder_issue.main(["--code", "5", "--record", str(tmp_path / "record.json"), "--existing", str(tmp_path / "issue.json"),
                                "--dry-run"]) == 0
    (action,) = json.loads(capsys.readouterr().out)
    assert action["do"] == "create" and "timed out" in action["body"]
