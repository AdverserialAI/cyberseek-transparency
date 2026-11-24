"""tools/check_published_policy.py, offline: the network and cosign are replaced."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_published_policy", ROOT / "tools" / "check_published_policy.py")
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)

POLICY = {
    "model_id": "adverserial/cyberseek", "proxy_version": "v0.1.0-rc.99",
    "deployment_configuration_digest": "sha256:" + "1" * 64, "runtime_image_digest": "sha256:" + "2" * 64,
    "tdx": {"mrtd": "a" * 96, "rtmr0": "b" * 96, "rtmr1": "c" * 96, "rtmr2": "d" * 96, "app_id": "e" * 40, "compose_hash": "f" * 64, "os_image_hash": "0" * 64},
}
BYTES = json.dumps(POLICY, indent=2).encode()
BUNDLE = b'{"mediaType": "test bundle"}'


class Cosign:
    def __init__(self, returncode=0):
        self.returncode, self.stdout, self.stderr, self.calls = returncode, "", "no matching CertificateIdentity", []

    def __call__(self, command, **_):
        self.calls.append(command)
        return self


@pytest.fixture
def deployments(tmp_path):
    release = tmp_path / "deployments" / "v0.1.0-rc.99"
    release.mkdir(parents=True)
    (tmp_path / "deployments" / "CURRENT").write_text("v0.1.0-rc.99\n# Status: a comment line\n")
    (release / "policy.json").write_text(json.dumps(POLICY))
    return tmp_path / "deployments"


def run(monkeypatch, capsys, deployments, site, mirror, cosign=None):
    cosign = cosign or Cosign()
    pages = {f"{watch.SITE}/{name}": body for name, body in site.items()}
    pages.update({f"{watch.SIGNED_RAW}/{name}": body for name, body in mirror.items()})
    monkeypatch.setattr(watch, "get", lambda url: pages.get(url))
    monkeypatch.setattr(watch.subprocess, "run", cosign)
    code = watch.main(["--deployments", str(deployments)])
    return code, capsys.readouterr().out, cosign


GOOD = {watch.POLICY: BYTES, watch.BUNDLE: BUNDLE}


def test_pass_when_site_equals_signed_branch_verifies_and_matches_the_deployment(monkeypatch, capsys, deployments):
    code, out, cosign = run(monkeypatch, capsys, deployments, GOOD, GOOD)
    assert code == 0 and "VERDICT: PASS" in out
    command = cosign.calls[0]
    assert command[command.index("--certificate-identity") + 1] == "https://github.com/AdverserialAI/confidential-policy/.github/workflows/sign-policy.yml@refs/heads/main"
    assert command[command.index("--certificate-oidc-issuer") + 1] == "https://token.actions.githubusercontent.com"
    assert command[command.index("--certificate-github-workflow-trigger") + 1] == "push"


def test_unsigned_policy_fails(monkeypatch, capsys, deployments):
    code, out, cosign = run(monkeypatch, capsys, deployments, {watch.POLICY: BYTES}, {})
    assert code == 1 and "[FAIL] policy.bundle_served" in out and not cosign.calls


def test_site_serving_other_bytes_than_the_signed_branch_fails(monkeypatch, capsys, deployments):
    code, out, _ = run(monkeypatch, capsys, deployments, {watch.POLICY: BYTES + b"\n", watch.BUNDLE: BUNDLE}, GOOD)
    assert code == 1 and "[FAIL] policy.matches_signed_branch" in out


def test_signature_from_another_identity_fails(monkeypatch, capsys, deployments):
    code, out, _ = run(monkeypatch, capsys, deployments, GOOD, GOOD, Cosign(returncode=1))
    assert code == 1 and "[FAIL] policy.signature" in out


def test_policy_pinning_another_workload_than_the_current_deployment_fails(monkeypatch, capsys, deployments):
    other = dict(POLICY, tdx=dict(POLICY["tdx"], compose_hash="9" * 64))
    (deployments / "v0.1.0-rc.99" / "policy.json").write_text(json.dumps(other))
    code, out, _ = run(monkeypatch, capsys, deployments, GOOD, GOOD)
    assert code == 1 and "tdx.compose_hash" in out


def test_pending_deployment_is_incomplete_not_a_failure(monkeypatch, capsys, deployments):
    pending = {key: value for key, value in POLICY.items() if key != "tdx"}
    pending.update(pending=True, tdx={"compose_hash": POLICY["tdx"]["compose_hash"]})
    (deployments / "v0.1.0-rc.99" / "policy.json").write_text(json.dumps(pending))
    code, out, _ = run(monkeypatch, capsys, deployments, GOOD, GOOD)
    assert code == 2 and "[SKIP] policy.matches_deployment" in out and "VERDICT: INCOMPLETE" in out
