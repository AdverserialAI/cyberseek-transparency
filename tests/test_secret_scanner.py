"""Every fake credential below is assembled at run time so that this file
itself contains nothing that a secret scanner (ours or GitHub's) would flag."""
import json

import pytest

import check_no_secrets as scanner

A = "A1b2C3d4E5f6G7h8J9k0L1m2N3p4Q5r6S7t8U9v0"  # 40 harmless characters


def rules(text, profile="strict"):
    return sorted({rule for _, rule, _ in scanner.scan_text(text, profile)})


@pytest.mark.parametrize("line,rule", [
    ("HF_TOKEN: " + "hf" + "_" + A[:34], "huggingface-token"),
    ("NV_ATTESTATION_SERVICE_KEY=" + "nv" + "api-" + A, "nvidia-api-key"),
    ("x " + "gh" + "p_" + A[:36], "github-token"),
    ("x " + "AK" + "IA" + "ABCDEFGHIJKLMNOP", "aws-access-key"),
    ("x " + "s" + "k-" + A, "sk-api-key"),
    ("-----BEGIN EC " + "PRIVATE KEY-----", "private-key-block"),
    ('{"kty":"EC","' + 'd":"' + A + '"}', "private-jwk-member"),
    ("url: https://user:" + A[:12] + "@example.com/x", "url-credentials"),
    ("Authorization: " + "Bearer " + A, "bearer-literal"),
])
def test_token_formats_are_detected(line, rule):
    assert rule in rules(line)


@pytest.mark.parametrize("name", ["RECEIPT_SIGNING_SEED", "METER_SIGNING_SEED", "CLOUDFLARE_API_TOKEN", "GANDI_PAT",
                                  "METER_INGRESS_SHARED_SECRET", "UPSTREAM_BEARER_TOKEN", "EHBP_IDENTITY_B64",
                                  "DB_PASSWORD", "BACKEND_API_KEY"])
@pytest.mark.parametrize("form", ["      {n}: {v}", "      - {n}={v}", "export {n}=\"{v}\"", "{n}='{v}'", '  "{n}": "{v}",'])
def test_literal_assigned_to_sensitive_variable_is_detected(name, form):
    assert "assignment" in rules(form.format(n=name, v=A))


@pytest.mark.parametrize("value", ["${HF_TOKEN}", "$HF_TOKEN", '"${HF_TOKEN}"', "${HF_TOKEN:?must be set}", "${HF_TOKEN:-}",
                                   "$$HF_TOKEN", "$(cat /run/secret)", "", '""', "<set at deploy time>", "true", "300"])
def test_references_and_placeholders_are_allowed(value):
    assert rules("      HF_TOKEN: " + value) == []
    assert rules("      - HF_TOKEN=" + value) == []


def test_default_values_inside_references_are_not_allowed():
    assert rules("      HF_TOKEN: ${HF_TOKEN:-" + A + "}") == ["assignment"]


@pytest.mark.parametrize("line", [
    "      COMPOSE_DIGEST: sha256:" + "ab" * 32,
    "    image: ghcr.io/example/attest-proxy@sha256:" + "ab" * 32,
    "      GPU_EVIDENCE_FILE: /run/gpu/evidence.json",
    "      METER_PUBLIC_KEY: " + A,
    "      RECEIPT_KEY_ID: " + A,
    "      TLS_KEY_FILE: /certs/tls.key",
    "      ENTITLEMENT_JWKS_JSON: '{\"keys\":[]}'",
    '  "key_provider_id": "' + "30" * 20 + '",',
    '    "compose_hash": "' + "ab" * 32 + '",',
    "      AUTH_REQUIRED: \"true\"",
    "      PORT: 8443",
])
def test_public_values_do_not_trigger(line):
    assert rules(line) == []


# Lines of the kind the first deployed enclave-key release (rc.33) compose contains: none is a secret.
@pytest.mark.parametrize("line", [
    "      UPSTREAM_BEARER_TOKEN_FILE: /run/handoff/upstream-token",
    "      ENCLAVE_KEY_DIR: /state/keys",
    "      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}",
    "      METER_INGRESS_SHARED_SECRET: ${METER_INGRESS_SHARED_SECRET}",
    "      NV_ATTESTATION_SERVICE_KEY: ${NV_ATTESTATION_SERVICE_KEY}",
    "      HF_TOKEN: ${HF_TOKEN}",
    "      TOKEN_FILE=/run/handoff/upstream-token",
    '      KEY="$$(head -c 200 "$$TOKEN_FILE" 2>/dev/null | tr -d \'\\r\\n\')"',
    '      case "$$KEY" in *[!A-Za-z0-9_-]*) KEY="" ;; esac',
    '      if [ "$${#KEY}" -lt 32 ]; then echo "FATAL: no usable upstream token in $$TOKEN_FILE" >&2; sleep 30; exit 1; fi',
    '      set -- "$$@" --api-key "$$KEY"',
    '        case "$$prev" in --port) PORT="$$a" ;; --api-key) KEY="$$a" ;; esac',
    '        SGL_PROBE_KEY="$$KEY" python3 -c \'import os,sys,urllib.request',
    '      r=urllib.request.Request(url,headers={"Authorization":"Bearer "+os.environ["SGL_PROBE_KEY"]})',
    "      path = '/handoff/upstream-token'",
    "          f.write(secrets.token_urlsafe(48))",
    "    - '--tool-call-parser'",
    "    - --max-total-tokens 4096",
    "    - --tokenizer-mode auto",
    "    - --ssl-keyfile-path /certs/tls.key",
    "      ENTITLEMENT_JWKS_JSON: '{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"" + A + "\",\"x\":\"" + A + "\",\"alg\":\"EdDSA\",\"use\":\"sig\"}]}'",
])
def test_enclave_key_release_lines_do_not_trigger(line):
    assert rules(line) == []


# ... and the same shapes holding a literal still do.
@pytest.mark.parametrize("line,rule", [
    ("      UPSTREAM_BEARER_TOKEN_FILE: " + A, "assignment"),          # a *_FILE name must hold a path
    ("      ENCLAVE_KEY_DIR: " + A, "assignment"),
    ("      UPSTREAM_BEARER_TOKEN: " + A, "assignment"),
    ("      TOKEN_FILE=" + A, "assignment"),
    ("      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN:-" + A + "}", "assignment"),
    ('      set -- "$$@" --api-key "' + A + '"', "flag-literal"),
    ("      python3 -m sglang.launch_server --api-key " + A, "flag-literal"),
    ("      python3 -m sglang.launch_server --api-key=" + A, "flag-literal"),
    ("      huggingface-cli download --token " + A, "flag-literal"),
    ('      KEY="' + A + '"', "assignment"),
])
def test_literals_in_the_same_shapes_are_still_detected(line, rule):
    assert rule in rules(line)


def test_flag_and_value_as_consecutive_list_items():
    assert rules("    - '--api-key'\n    - '%s'\n" % A) == ["flag-literal"]
    assert rules("    - --api-key\n    - %s\n" % A) == ["flag-literal"]
    assert rules("    - '--api-key'\n    - '$$KEY'\n") == []
    assert rules("    - '--port'\n    - '30000'\n    - '--served-model-name'\n    - 'adverserial/cyberseek'\n") == []


def test_release_compose_is_clean(tmp_path):
    """The real release compose, when its path is supplied: no finding, as text and inside an app-compose.json."""
    from conftest import require
    text = require("AV_FIXTURE_RELEASE_COMPOSE").read_text()
    assert scanner.scan_text(text) == []
    manifest = tmp_path / "app-compose.json"
    manifest.write_text(json.dumps({"docker_compose_file": text, "allowed_envs": ["HF_TOKEN"], "pre_launch_script": ""}))
    assert scanner.scan_file(manifest) == []


def test_jwt_only_in_strict_profile():
    jwt = "ey" + "J" + A[:20] + "." + "ey" + "J" + A[:20] + "." + A[:20]
    assert rules("token " + jwt) == ["jwt"]
    assert rules("token " + jwt, "evidence") == []


def test_findings_never_contain_the_value():
    secret = "hf" + "_" + A[:34]
    for _, _, description in scanner.scan_text("HF_TOKEN: " + secret):
        assert secret not in description and A[:10] not in description


def test_json_files_are_scanned_inside_embedded_strings(tmp_path):
    compose_text = "services:\n  a:\n    environment:\n      RECEIPT_SIGNING_SEED: %s\n      OK: ${HF_TOKEN}\n" % A
    f = tmp_path / "app-compose.json"
    f.write_text(json.dumps({"docker_compose_file": compose_text, "key_provider": None, "allowed_envs": ["HF_TOKEN"]}))
    findings = scanner.scan_file(f)
    assert len(findings) == 1 and "RECEIPT_SIGNING_SEED" in findings[0] and A not in findings[0]
    f.write_text(json.dumps({"api_token": A}))
    assert any("api_token" in line for line in scanner.scan_file(f))


def test_cli_exit_codes(tmp_path, capsys):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "docker-compose.yml").write_text("services:\n  a:\n    environment:\n      HF_TOKEN: ${HF_TOKEN}\n")
    assert scanner.main([str(clean)]) == 0
    (clean / "leak.env").write_text("GANDI_PAT=%s\n" % A)
    assert scanner.main([str(clean)]) == 1
    out = capsys.readouterr().out
    assert "GANDI_PAT" in out and A not in out
    (clean / "leak.env").unlink()
    (clean / "blob.bin").write_bytes(b"\xff\xfe\x00")
    assert scanner.main([str(clean)]) == 1                           # strict: unscannable files are refused
    assert scanner.main(["--profile", "evidence", str(clean)]) == 0
    assert scanner.main([str(tmp_path / "missing")]) == 2


def test_repository_deployments_are_clean():
    from conftest import ROOT
    assert scanner.main([str(ROOT / "deployments")]) == 0


# ---- the "source" profile: program text, tests, workflows, documentation ----

@pytest.mark.parametrize("line", [
    "HF_TOKEN: " + "hf" + "_" + A[:34],
    "-----BEGIN EC " + "PRIVATE KEY-----",
    "Authorization: " + "Bearer " + A,
    "RECEIPT_SIGNING_SEED = '" + A + "'",
    '  "meter_signing_seed": "' + "ab" * 32 + '",',
    "export GANDI_PAT=" + A,
    "x " + "ey" + "J" + A[:20] + "." + "ey" + "J" + A[:20] + "." + A[:20],
])
def test_source_profile_catches_credential_shaped_literals(line):
    assert rules(line, "source") != []


@pytest.mark.parametrize("line", [
    "        key = serialization.load_der_public_key(binding.receipt_spki_der(jwk))",
    "        self.root_key = ec.generate_private_key(ec.SECP256R1())",
    "      id-token: write",
    "          GH_TOKEN: ${{ github.token }}",
    "      CLOUDFLARE_API_TOKEN: ${CLOUDFLARE_API_TOKEN}",
    "      UPSTREAM_BEARER_TOKEN_FILE: /run/handoff/upstream-token",
    "      enclave_key_proxy_digests: sha256:" + "ab" * 32,
    "      METER_PUBLIC_KEY: " + A,
    'A = "' + A + '"',
])
def test_source_profile_leaves_code_alone(line):
    assert rules(line, "source") == []


def test_source_profile_reads_json_and_refuses_binaries(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"service": {"api_token": A}}))
    (tmp_path / "b.json").write_text(json.dumps({"service": {"api_token": "${API_TOKEN}", "public_key": A}}))
    (tmp_path / "c.bin").write_bytes(b"\xff\xfe\x00")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.pyc").write_bytes(b"\xff\xfe\x00")
    assert [f.split(":")[0].rsplit("/", 1)[1] for f in scanner.scan_file(tmp_path / "a.json", "source")] == ["a.json", "a.json"]
    assert scanner.scan_file(tmp_path / "b.json", "source") == []
    assert "binary-file" in scanner.scan_file(tmp_path / "c.bin", "source")[0]
    assert [f.name for f in scanner.iter_files([str(tmp_path)])] == ["a.json", "b.json", "c.bin"]


def test_the_whole_repository_passes_the_source_profile():
    """What CI runs: nothing anywhere in the repository is shaped like a credential."""
    from conftest import ROOT
    assert scanner.main(["--profile", "source", str(ROOT)]) == 0
