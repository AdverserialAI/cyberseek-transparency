"""The strict YAML reader and the structural compose checks, on the synthetic
compose (same shape as the first enclave-key release) and, when its path is
supplied, on the real release compose."""
import pytest

import synth
from avlib import compose, miniyaml
from conftest import require

PROXY, INFERENCE = "attest-proxy", "sglang"


def text():
    return synth.make_compose()[0]


def edited(old: str, new: str) -> str:
    t = text()
    assert t.count(old) >= 1, old
    return t.replace(old, new, 1)


def keys_check(t: str, allowed=synth.SEALED, digests=(synth.PROXY_DIGEST,), policy_digest=synth.PROXY_DIGEST, banned=None):
    return compose.check_keys_in_enclave(compose.load(t), t, allowed, PROXY, banned, digests, policy_digest)


# ---- the reader ------------------------------------------------------------
def test_reader_understands_the_compose_shape():
    doc = miniyaml.load(text())
    proxy = doc["services"][PROXY]
    assert proxy["ports"] == [{"mode": "ingress", "target": "8443", "published": "443", "protocol": "tcp"}]
    assert proxy["networks"] == {"default": None, "inference": None} and proxy["cap_drop"] == ["ALL"]
    assert proxy["environment"]["CONFIDENTIAL_MODE"] == "1" and proxy["volumes"][0]["volume"] == {}
    assert proxy["environment"]["ENTITLEMENT_JWKS_JSON"].startswith('{"keys":[')
    assert doc["networks"]["inference"] == {"name": "dstack_inference", "internal": "true"}
    command = doc["services"][INFERENCE]["command"]
    assert command[1:] == ["sglang", "--port", "30000"] and command[0].startswith("set -u\nKEY=") and command[0].endswith('"$$@"\n')
    assert doc["services"]["model-download"]["command"][0].startswith('set -euo pipefail; marker="/data/')


def test_reader_scalars_and_block_scalars():
    doc = miniyaml.load("a: 'it''s'  # note\nb: \"x\\ny\"\nc: |-\n  one\n\n  two\nd: ~\ne: [1, \"two\"]\nf:\n- x\n- k: v\n  l: w\ng: plain # comment\n")
    assert doc == {"a": "it's", "b": "x\ny", "c": "one\n\ntwo", "d": None, "e": [1, "two"], "f": ["x", {"k": "v", "l": "w"}], "g": "plain"}


@pytest.mark.parametrize("bad", [
    "a: &anchor 1\n",                      # anchor
    "a: *alias\n",                         # alias
    "base: {}\nservices:\n  <<: *base\n",  # merge key
    "a: !!python/object x\n",              # tag
    "a: 1\n---\nb: 2\n",                   # second document
    "a: 1\na: 2\n",                        # duplicate key
    "a:\n\tb: 1\n",                        # tab indentation
    "a: one\n  two\n",                     # multi-line plain scalar
    "a: \"unterminated\n",                 # multi-line quoted scalar
    "a: {b: c}\n",                         # non-JSON flow mapping
    "- a\n",                               # top level is not a mapping
    "a: |2\n    x\n",                      # indentation indicator
    "a\n",                                 # not key: value
])
def test_reader_rejects_what_it_does_not_support(bad):
    with pytest.raises(miniyaml.YAMLError):
        miniyaml.load(bad)


# ---- the good compose ------------------------------------------------------
def test_good_compose_passes_every_structural_check():
    doc = compose.load(text())
    assert compose.sealed_references(doc) == set(synth.SEALED)
    assert len(compose.check_images(doc)) == 4
    assert "internal: true" in compose.check_inference_isolated(doc, INFERENCE, PROXY)
    assert "443->8443" in compose.check_single_ingress(doc, PROXY)
    compose.check_sealed_envs(doc, synth.SEALED, synth.SEALED)
    detail = keys_check(text())
    assert "gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@" + synth.PROXY_DIGEST + " -R AdverserialAI/attest-proxy" in detail


def test_interpolation_honours_the_dollar_escape():
    assert compose.interpolations('KEY="$$(cat x)"; echo "$${#KEY}" $$KEY $$@') == []
    assert compose.interpolations("${A} $B ${C:-default} $$D") == ["A", "B", "C"]


# ---- keys generated in the enclave -----------------------------------------
@pytest.mark.parametrize("old,new,why", [
    ("      ENCLAVE_KEY_DIR: /state/keys\n", "", "ENCLAVE_KEY_DIR"),
    ("      UPSTREAM_BEARER_TOKEN_FILE: /run/handoff/upstream-token\n", "", "UPSTREAM_BEARER_TOKEN_FILE"),
    ("      ENCLAVE_KEY_DIR: /state/keys\n", "      ENCLAVE_KEY_DIR: ${HF_TOKEN}\n", "ENCLAVE_KEY_DIR"),
    ("      CONFIDENTIAL_MODE: '1'\n", "      CONFIDENTIAL_MODE: '0'\n", "CONFIDENTIAL_MODE"),
    ("      CONFIDENTIAL_MODE: '1'\n", "", "CONFIDENTIAL_MODE"),
    ("      ENCLAVE_KEY_DIR:", "      RECEIPT_SIGNING_SEED: ${RECEIPT_SIGNING_SEED}\n      ENCLAVE_KEY_DIR:", "RECEIPT_SIGNING_SEED"),
    ("      ENCLAVE_KEY_DIR:", "      METER_SIGNING_SEED: ''\n      ENCLAVE_KEY_DIR:", "METER_SIGNING_SEED"),
    ("      ENCLAVE_KEY_DIR:", "      EHBP_IDENTITY_B64: x\n      ENCLAVE_KEY_DIR:", "EHBP_IDENTITY_B64"),
    ("      ENCLAVE_KEY_DIR:", "      UPSTREAM_BEARER_TOKEN: ${HF_TOKEN}\n      ENCLAVE_KEY_DIR:", "UPSTREAM_BEARER_TOKEN"),
    # a banned variable on another service is refused too: nothing in the release may carry one
    ("      MODEL_REVISION:", "      METER_SIGNING_SEED: ${HF_TOKEN}\n      MODEL_REVISION:", "METER_SIGNING_SEED"),
    # a literal that looks like a credential, anywhere in the file
    ("      MODEL_REVISION:", "      BACKEND_API_KEY: " + "Zz9" * 14 + "\n      MODEL_REVISION:", "literal credential"),
    ('--api-key "$$KEY"', "--api-key " + "Zz9" * 14, "literal credential"),
])
def test_keys_in_enclave_requires_each_condition(old, new, why):
    with pytest.raises(compose.ComposeViolation, match=why):
        keys_check(edited(old, new))


def test_keys_in_enclave_depends_on_the_proxy_build():
    with pytest.raises(compose.ComposeViolation, match="not listed"):
        keys_check(text(), digests=())                                     # policy vouches for no build
    with pytest.raises(compose.ComposeViolation, match="not listed"):
        keys_check(text(), digests=("sha256:" + "ee" * 32,))               # ... or for a different one
    with pytest.raises(compose.ComposeViolation, match="proxy_image_digest"):
        keys_check(text(), policy_digest="sha256:" + "ee" * 32)
    with pytest.raises(compose.ComposeViolation, match="UPSTREAM_BEARER_TOKEN"):
        keys_check(text(), allowed=synth.SEALED + ["UPSTREAM_BEARER_TOKEN"])  # injectable through allowed_envs
    with pytest.raises(compose.ComposeViolation, match="HF_TOKEN"):
        keys_check(text(), banned=["HF_TOKEN"])                            # a policy can add names ...
    assert "UPSTREAM_BEARER_TOKEN" in keys_check(text(), banned=[])        # ... but never remove the built-in ones


# ---- network isolation and the single ingress ------------------------------
@pytest.mark.parametrize("old,new,why", [
    ("    networks:\n      inference: null\n    volumes:", "    network_mode: host\n    volumes:", "network_mode"),
    ("    networks:\n      inference: null\n    volumes:", "    network_mode: service:attest-proxy\n    volumes:", "network_mode"),
    ("    networks:\n      inference: null\n    volumes:", "    volumes:", "default"),
    ("    networks:\n      inference: null\n    volumes:", "    networks:\n      inference: null\n      default: null\n    volumes:", "not declared internal"),
    ("    networks:\n      inference: null\n    volumes:", "    networks:\n      inference: null\n    ports:\n    - 30000:30000\n    volumes:", "publishes ports"),
    ("    name: dstack_inference\n    internal: true\n", "    name: dstack_inference\n", "not declared internal"),
    ("    name: dstack_inference\n    internal: true\n", "    name: dstack_inference\n    internal: false\n", "not declared internal"),
    # a third container on the internal network could talk to the model server
    ("    image: ghcr.io/example/collector@" + synth.HELPER_DIGEST + "\n    networks:\n      default: null\n",
     "    image: ghcr.io/example/collector@" + synth.HELPER_DIGEST + "\n    networks:\n      inference: null\n", "shared with"),
])
def test_inference_isolation_requires_each_condition(old, new, why):
    with pytest.raises(compose.ComposeViolation, match=why):
        compose.check_inference_isolated(compose.load(edited(old, new)), INFERENCE, PROXY)


@pytest.mark.parametrize("old,new,why", [
    ("    network_mode: none\n", "    network_mode: host\n", "network_mode"),
    ("    network_mode: none\n", "    ports:\n    - '8080:8080'\n", "publishes ports"),
    ("    ports:\n    - mode: ingress\n      target: 8443\n      published: '443'\n      protocol: tcp\n", "", "publishes no port"),
])
def test_single_ingress_requires_each_condition(old, new, why):
    with pytest.raises(compose.ComposeViolation, match=why):
        compose.check_single_ingress(compose.load(edited(old, new)), PROXY)


def test_missing_services_are_reported():
    doc = compose.load(text())
    for fn in (lambda: compose.check_inference_isolated(doc, "vllm", PROXY), lambda: compose.check_single_ingress(doc, "gateway")):
        with pytest.raises(compose.ComposeViolation, match="no service named"):
            fn()


# ---- images and sealed variables -------------------------------------------
@pytest.mark.parametrize("old,new", [
    ("example/inference@" + synth.INFERENCE_DIGEST, "example/inference:latest"),
    ("example/inference@" + synth.INFERENCE_DIGEST, "example/inference@sha256:abcd"),
    ("    image: example/inference@" + synth.INFERENCE_DIGEST + "\n", "    build: .\n"),
    ("    image: example/inference@" + synth.INFERENCE_DIGEST + "\n", ""),
])
def test_every_image_must_be_pinned(old, new):
    with pytest.raises(compose.ComposeViolation):
        compose.check_images(compose.load(edited(old, new)))


def test_sealed_variables_must_equal_the_policy_and_the_manifest():
    doc = compose.load(text())
    for app_allowed, policy_allowed in ((synth.SEALED[:3], synth.SEALED), (synth.SEALED, synth.SEALED[:3]),
                                        (synth.SEALED + ["EXTRA"], synth.SEALED), (synth.SEALED, synth.SEALED + ["EXTRA"])):
        with pytest.raises(compose.ComposeViolation, match="differ"):
            compose.check_sealed_envs(doc, app_allowed, policy_allowed)


@pytest.mark.parametrize("old,new", [
    ("ghcr.io/example/attest-proxy@" + synth.PROXY_DIGEST, "ghcr.io/example/attest-proxy@${PROXY_DIGEST}"),   # image
    ("      published: '443'\n", "      published: ${PORT}\n"),                                              # port
    ("      UPSTREAM: http://sglang:30000\n", "      UPSTREAM: http://${UPSTREAM_HOST}:30000\n"),             # part of a value
    ("      HF_TOKEN: ${HF_TOKEN}\n", "      HF_TOKEN: ${HF_TOKEN:-fallback}\n"),                             # default value
    ('--api-key "$$KEY"', '--api-key "$KEY"'),                                                                # unescaped in a command
])
def test_deploy_time_substitution_is_only_allowed_as_a_whole_environment_value(old, new):
    with pytest.raises(compose.ComposeViolation, match="substitution"):
        compose.sealed_references(compose.load(edited(old, new)))


def test_pass_through_and_list_form_environment_count_as_sealed():
    t = edited("      HF_TOKEN: ${HF_TOKEN}\n      MODEL_REVISION: 0123456789abcdef\n", "    - HF_TOKEN=${HF_TOKEN}\n    - EXTRA_FROM_HOST\n")
    assert compose.sealed_references(compose.load(t)) == set(synth.SEALED) | {"EXTRA_FROM_HOST"}


@pytest.mark.parametrize("extra", ["include:\n- other.yml\n", "  x:\n    image: a@sha256:" + "00" * 32 + "\n    env_file: .env\n",
                                   "  x:\n    extends:\n      file: other.yml\n      service: y\n"])
def test_configuration_from_outside_the_measured_file_is_refused(extra):
    t = text()
    t = extra + t if extra.startswith("include") else t.replace("networks:\n  default:\n", extra + "networks:\n  default:\n")
    with pytest.raises(compose.ComposeViolation, match="outside the measured file"):
        compose.load(t)


# ---- the real release compose (path supplied by the environment) -----------
def test_release_compose_passes_every_structural_check():
    path = require("AV_FIXTURE_RELEASE_COMPOSE")
    t = path.read_text()
    doc = compose.load(t)
    sealed = ["CLOUDFLARE_API_TOKEN", "HF_TOKEN", "METER_INGRESS_SHARED_SECRET", "NV_ATTESTATION_SERVICE_KEY"]
    assert compose.sealed_references(doc) == set(sealed)
    compose.check_images(doc)
    compose.check_inference_isolated(doc, INFERENCE, PROXY)
    compose.check_single_ingress(doc, PROXY)
    compose.check_sealed_envs(doc, sealed, sealed)
    digest = compose.image_digest(doc["services"][PROXY])
    compose.check_keys_in_enclave(doc, t, sealed, PROXY, None, [digest], digest)
    declared, computed = compose.self_digest(t)
    assert declared == computed


def test_release_compose_passes_the_whole_verifier(fake_dcap):
    """The real release compose as the measured compose of a synthetic VM: every check passes."""
    import json
    from avlib import checks
    t = require("AV_FIXTURE_RELEASE_COMPOSE").read_text()
    sealed = ["CLOUDFLARE_API_TOKEN", "HF_TOKEN", "METER_INGRESS_SHARED_SECRET", "NV_ATTESTATION_SERVICE_KEY"]
    app = {"allowed_envs": sealed, "docker_compose_file": t, "kms_enabled": True, "manifest_version": 2, "name": "cyberseek",
           "runner": "docker-compose", "pre_launch_script": "#!/bin/sh\ntrue\n"}
    dep = synth.Deployment().use_compose(t, compose.canonical_app_compose(app))
    doc = compose.load(t)
    inp = dep.inputs(collateral_json=fake_dcap)
    inp.policy["proxy_image_digest"] = compose.image_digest(doc["services"][PROXY])
    inp.policy["runtime_image_digest"] = compose.image_digest(doc["services"][INFERENCE])
    inp.policy["verifier"].update(allowed_envs=sealed, enclave_key_proxy_digests=[inp.policy["proxy_image_digest"]])
    result = checks.run(inp)
    assert {c["id"]: c["status"] for c in result.checks if c["status"] not in ("PASS", "N/A")} == {}
    assert result.verdict == "PASS"
