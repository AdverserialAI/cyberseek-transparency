"""tools/prepare_release.py: a VM description, a policy and a tag become a release directory, or nothing at all."""
import json
import shutil

import pytest

import prepare_release
import synth
import validate_deployments
from avlib import compose
from conftest import PLACEHOLDER_DEPLOYMENTS, require

TAG = "v0.0.1-test"
FAKE = "Zz9" * 14  # shaped like a credential, assembled at run time


def snapshot(dep: synth.Deployment, **changes) -> dict:
    """The fields of `phala cvms get <id> --json` that matter, for a synthetic deployment."""
    app = json.loads(dep.app_compose)
    doc = {"success": True, "app_id": synth.APP_ID, "compose_hash": dep.compose_hash,
           "docker_compose_hash": compose.sha256_hex(dep.compose_text.encode()), "os": {"os_image_hash": synth.OS_IMAGE_HASH},
           "compose_file": dict(app, bash_script=None, init_script=[], key_provider=None)}
    doc.update(changes)
    return doc


@pytest.fixture
def repo(tmp_path):
    deployments = tmp_path / "deployments"
    shutil.copytree(PLACEHOLDER_DEPLOYMENTS, deployments)
    return deployments


def run(tmp_path, deployments, snap, policy, *extra):
    (tmp_path / "cvm.json").write_text(json.dumps(snap))
    (tmp_path / "policy.json").write_text(json.dumps(policy, indent=2))
    return prepare_release.main([str(tmp_path / "cvm.json"), str(tmp_path / "policy.json"), TAG, "--deployments", str(deployments), *extra])


def untouched(deployments):
    return (not (deployments / TAG).exists() and (deployments / "CURRENT").read_text() == (PLACEHOLDER_DEPLOYMENTS / "CURRENT").read_text()
            and (deployments / "CHANGELOG.md").read_text() == (PLACEHOLDER_DEPLOYMENTS / "CHANGELOG.md").read_text()
            and not any(p.name.startswith(".staging") for p in deployments.iterdir()))


def test_writes_a_release_that_validates(tmp_path, repo, deployment, capsys):
    code = run(tmp_path, repo, snapshot(deployment), deployment.policy(), "--retire-placeholder",
               "--rolled-out", "2030-01-15 12:00 UTC", "--changes", "test release")
    assert code == 0, capsys.readouterr().err
    d = repo / TAG
    assert sorted(p.name for p in d.iterdir()) == ["app-compose.json", "docker-compose.yml", "policy.json"]
    assert (d / "app-compose.json").read_bytes() == deployment.app_compose            # canonical: sha256sum gives the compose hash
    assert (d / "docker-compose.yml").read_bytes() == deployment.compose_text.encode()
    assert (d / "policy.json").read_bytes() == (tmp_path / "policy.json").read_bytes()
    assert (repo / "CURRENT").read_text() == TAG + "\n"
    changelog = (repo / "CHANGELOG.md").read_text()
    assert "## %s\n- Rolled out: 2030-01-15 12:00 UTC\n- Changes: test release\n" % TAG in changelog
    assert deployment.compose_hash in changelog and "## PENDING" not in changelog and not (repo / "PENDING").exists()
    assert validate_deployments.main([str(repo)]) == 0                                 # no placeholders left, release valid
    capsys.readouterr()
    assert run(tmp_path, repo, snapshot(deployment), deployment.policy()) == 1         # immutable: never rewritten
    assert "already exists" in capsys.readouterr().err


def test_dry_run_and_placeholder_reminder(tmp_path, repo, deployment, capsys):
    assert run(tmp_path, repo, snapshot(deployment), deployment.policy(), "--dry-run") == 0
    assert untouched(repo)
    assert run(tmp_path, repo, snapshot(deployment), deployment.policy()) == 0
    out = capsys.readouterr().out
    assert "TO BE FILLED IN" in out and "PENDING is still a placeholder" in out and (repo / "PENDING").exists()


def test_refuses_on_any_hash_mismatch(tmp_path, repo, deployment, capsys):
    good = snapshot(deployment)
    cases = {
        "the VM reports compose_hash": dict(good, compose_hash="00" * 32),
        "docker_compose_hash": dict(good, docker_compose_hash="00" * 32),
        "no \"compose_hash\"": {k: v for k, v in good.items() if k != "compose_hash"},
        "no \"compose_file\"": {k: v for k, v in good.items() if k != "compose_file"},
        "policy.tdx.app_id": dict(good, app_id="cd" * 20),
        "policy.tdx.os_image_hash": dict(good, os={"os_image_hash": "ef" * 32}),
        # the manifest was edited after the hash was taken (an extra operator-settable variable)
        "hash mismatch": dict(good, compose_file=dict(good["compose_file"], allowed_envs=synth.SEALED + ["UPSTREAM"])),
    }
    for expected, snap in cases.items():
        assert run(tmp_path, repo, snap, deployment.policy()) == 1, expected
        assert expected in capsys.readouterr().err, expected
        assert untouched(repo), expected

    for field, value, expected in (("compose_hash", "00" * 32, "policy.tdx.compose_hash"),
                                   ("mrtd", "xyz", "policy.tdx.mrtd")):
        policy = deployment.policy()
        policy["tdx"][field] = value
        assert run(tmp_path, repo, good, policy) == 1
        assert expected in capsys.readouterr().err and untouched(repo)
    policy = dict(deployment.policy(), deployment_configuration_digest="sha256:" + "00" * 32)
    assert run(tmp_path, repo, good, policy) == 1
    assert "deployment_configuration_digest" in capsys.readouterr().err and untouched(repo)


def test_refuses_on_any_secret_finding(tmp_path, repo, capsys):
    # 1. a literal in the compose: the hash is right, the policy is right, it is still refused
    template = synth.COMPOSE_TEMPLATE.replace("      MODEL_REVISION:", "      GANDI_PAT: %s\n      MODEL_REVISION:" % FAKE)
    leaky = synth.Deployment().use_compose(*synth.finish_compose(template))
    assert run(tmp_path, repo, snapshot(leaky), leaky.policy()) == 1
    err = capsys.readouterr().err
    assert "GANDI_PAT" in err and FAKE not in err and untouched(repo)

    # 2. a literal in the pre-launch script inside the manifest
    dep = synth.Deployment()
    app = dict(json.loads(dep.app_compose), pre_launch_script="#!/bin/sh\nexport REGISTRY_PASSWORD=%s\n" % FAKE)
    dep.use_compose(dep.compose_text, compose.canonical_app_compose(app))
    assert run(tmp_path, repo, snapshot(dep), dep.policy()) == 1
    err = capsys.readouterr().err
    assert "REGISTRY_PASSWORD" in err and FAKE not in err and untouched(repo)

    # 3. a literal in the policy
    dep = synth.Deployment()
    assert run(tmp_path, repo, snapshot(dep), dict(dep.policy(), billing_api_token=FAKE)) == 1
    err = capsys.readouterr().err
    assert "billing_api_token" in err and FAKE not in err and untouched(repo)


def test_refuses_a_release_the_verifier_would_fail(tmp_path, repo, capsys):
    exposed = synth.Deployment().use_compose(*synth.finish_compose(
        synth.COMPOSE_TEMPLATE.replace("    name: dstack_inference\n    internal: true\n", "    name: dstack_inference\n")))
    assert run(tmp_path, repo, snapshot(exposed), exposed.policy()) == 1
    assert "not declared internal" in capsys.readouterr().err and untouched(repo)

    dep = synth.Deployment()
    policy = dep.policy()
    policy["verifier"]["allowed_envs"] = synth.SEALED[:2]
    assert run(tmp_path, repo, snapshot(dep), policy) == 1
    assert "operator-supplied variables differ" in capsys.readouterr().err and untouched(repo)

    policy = dep.policy()
    policy["verifier"]["enclave_key_proxy_digests"] = []
    assert run(tmp_path, repo, snapshot(dep), policy) == 1
    assert "refuses operator-supplied keys" in capsys.readouterr().err and untouched(repo)

    placeholder = json.loads((PLACEHOLDER_DEPLOYMENTS / "PENDING" / "policy.json").read_text())
    assert run(tmp_path, repo, snapshot(dep), placeholder) == 1
    assert "placeholder" in capsys.readouterr().err and untouched(repo)


def test_bad_tag_is_a_usage_error(tmp_path, repo, deployment):
    (tmp_path / "cvm.json").write_text(json.dumps(snapshot(deployment)))
    (tmp_path / "policy.json").write_text(json.dumps(deployment.policy()))
    for tag in ("../escape", "rc.33", "v1/2", ""):
        assert prepare_release.main([str(tmp_path / "cvm.json"), str(tmp_path / "policy.json"), tag, "--deployments", str(repo)]) == 2


def test_rc30_fixture_is_refused(tmp_path, repo, capsys):
    """The rc.30 VM description carries literal secrets and operator-provisioned keys: it can never be published."""
    cvm, policy = require("AV_FIXTURE_CVM", "AV_FIXTURE_POLICY")
    code = prepare_release.main([str(cvm), str(policy), TAG, "--deployments", str(repo)])
    err = capsys.readouterr().err
    assert code == 1 and untouched(repo)
    assert "RECEIPT_SIGNING_SEED" in err and "assignment" in err
    for line in err.splitlines():
        assert len(line) < 400  # names, rules and lengths only
