"""Deployment validation, canonicalisation and the history recorder, on synthetic data."""
import json
import shutil

import chainlib
import canonicalize_app_compose
import record
import synth
import validate_deployments
from conftest import PLACEHOLDER_DEPLOYMENTS


def make_repo(tmp_path, dep: synth.Deployment, release="v0.0.0-test"):
    root = tmp_path / "repo"
    d = root / "deployments" / release
    d.mkdir(parents=True)
    (d / "policy.json").write_text(json.dumps(dep.policy(), indent=2))
    (d / "app-compose.json").write_bytes(dep.app_compose)
    (d / "docker-compose.yml").write_text(dep.compose_text)
    (root / "deployments" / "CURRENT").write_text(release + "\n")
    (root / "deployments" / "CHANGELOG.md").write_text("# Changelog\n\n## %s\n- test\n" % release)
    (root / "history").mkdir()
    return root


def test_valid_release_passes_validation(tmp_path, deployment):
    root = make_repo(tmp_path, deployment)
    assert validate_deployments.main([str(root / "deployments")]) == 0
    assert list(validate_deployments.load_measurements(root / "deployments")) == ["v0.0.0-test"]


def test_validation_catches_each_inconsistency(tmp_path, deployment):
    root = make_repo(tmp_path, deployment)
    d = root / "deployments" / "v0.0.0-test"
    changelog = (root / "deployments" / "CHANGELOG.md").read_text()

    def errors():
        return " | ".join(validate_deployments.validate_release(d, changelog))

    assert errors() == ""
    original = (d / "docker-compose.yml").read_text()
    (d / "docker-compose.yml").write_text(original + "# edit\n")
    assert "differs from docker_compose_file" in errors() and "recomputes" in errors()
    (d / "docker-compose.yml").write_text(original)

    (d / "app-compose.json").write_text(json.dumps(json.loads(deployment.app_compose), indent=2))
    assert "not in canonical form" in errors()
    (d / "app-compose.json").write_bytes(deployment.app_compose)

    (d / "extra.env").write_text("METER_SIGNING_SEED=%s\n" % ("Zz9" * 14))
    assert "METER_SIGNING_SEED" in errors()
    (d / "extra.env").unlink()

    assert "no '## other' section" in " | ".join(validate_deployments.validate_release(d, changelog.replace("v0.0.0-test", "x")) + ["no '## other' section"])
    assert "CHANGELOG" in " | ".join(validate_deployments.validate_release(d, "# empty\n"))

    (root / "deployments" / "CURRENT").write_text("missing\n")
    assert validate_deployments.main([str(root / "deployments")]) == 1


def test_placeholder_release_is_an_error_unless_allowed():
    assert validate_deployments.main([str(PLACEHOLDER_DEPLOYMENTS)]) == 1
    assert validate_deployments.main([str(PLACEHOLDER_DEPLOYMENTS), "--allow-placeholders"]) == 0


def test_canonicalize_refuses_secrets_and_wrong_hash(tmp_path, deployment, capsys):
    app = json.loads(deployment.app_compose)
    snapshot = {"compose_hash": deployment.compose_hash, "compose_file": dict(app, bash_script=None, init_script=[])}
    src = tmp_path / "cvm.json"
    src.write_text(json.dumps(snapshot))
    out = tmp_path / "out"
    assert canonicalize_app_compose.main([str(src), "--out", str(out)]) == 0
    assert (out / "app-compose.json").read_bytes() == deployment.app_compose
    assert (out / "docker-compose.yml").read_text() == deployment.compose_text

    src.write_text(json.dumps(dict(snapshot, compose_hash="00" * 32)))
    assert canonicalize_app_compose.main([str(src), "--out", str(tmp_path / "bad")]) == 1

    leaky = dict(snapshot["compose_file"], docker_compose_file=deployment.compose_text + "      GANDI_PAT: %s\n" % ("Qq7" * 14))
    src.write_text(json.dumps({"compose_file": leaky}))
    assert canonicalize_app_compose.main([str(src), "--out", str(tmp_path / "leak")]) == 1
    assert not (tmp_path / "leak").exists() and not (tmp_path / "bad").exists()
    assert "Qq7" not in capsys.readouterr().err


def run_recorder(root, evidence_file, at, extra=()):
    return record.main(["--root", str(root), "--file", str(evidence_file), "--at", at, "--offline", *extra])


def test_recorder_appends_chain_and_stores_evidence(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment)
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(deployment.response()))
    # Synthetic evidence is not signed under Intel's root, so the verdict is FAIL (exit 1);
    # the point here is that the run is recorded faithfully anyway.
    assert run_recorder(root, evidence, "2030-01-15T12:00:00Z") == 1
    assert run_recorder(root, evidence, "2030-01-15T12:30:00Z") == 1
    capsys.readouterr()
    history = root / "history" / "attestations.jsonl"
    count, head = chainlib.validate(history, root)
    assert count == 2
    first, second = [json.loads(line) for line in chainlib.read_lines(history)]
    assert first["prev"] == chainlib.GENESIS and second["seq"] == 1
    assert first["verdict"] == "FAIL" and first["failed"] == ["tdx.quote_signature"]
    assert first["deployment"] == "v0.0.0-test" and first["expected_deployment"] == "v0.0.0-test"
    assert first["compose_hash"] == deployment.compose_hash and first["measurements"]["rtmr3"] == deployment.rtmrs[3]
    assert first["key_fingerprints"]["receipt_kid"] == deployment.receipt_jwk["kid"]
    assert first["tls_spki_sha256"].startswith("sha256:") and first["measurements_changed"] is False
    stored = root / first["files"]["evidence"]["path"]
    assert stored.read_bytes() == evidence.read_bytes()
    assert first["files"]["evidence"]["path"].startswith("history/evidence/2030/01/15/120000Z-")
    assert first["evidence_sha256"] == chainlib.line_hash(evidence.read_bytes())
    assert json.loads((stored.parent / "verifier.json").read_text())["verdict"] == "FAIL"

    # tampering with stored evidence is caught by the checker
    stored.write_bytes(stored.read_bytes() + b" ")
    import check_chain
    assert check_chain.main(["--root", str(root)]) == 1
    assert check_chain.main(["--root", str(root), "--no-files", "--expect-head", head]) == 0
    assert check_chain.main(["--root", str(root), "--no-files", "--expect-head", "00" * 32]) == 1


def test_recorder_stores_key_attestation_meter_jwks_and_statusz(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment)
    files = {"evidence": deployment.response(), "key-attestation": deployment.key_attestation(),
             "meter-jwks": deployment.meter_jwks(), "statusz": deployment.statusz()}
    for name, doc in files.items():
        (tmp_path / (name + ".json")).write_text(json.dumps(doc))
    extra = ["--key-attestation-file", str(tmp_path / "key-attestation.json"), "--meter-jwks-file", str(tmp_path / "meter-jwks.json"),
             "--statusz-file", str(tmp_path / "statusz.json")]
    assert run_recorder(root, tmp_path / "evidence.json", "2030-01-15T12:00:00Z", extra) == 1   # synthetic root: FAIL, as above
    capsys.readouterr()
    (entry,) = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert entry["failed"] == ["tdx.quote_signature", "keyatt.quote"]            # only the two Intel-root checks
    assert entry["keys_origin"] == "enclave-generated"
    assert entry["key_fingerprints"]["meter_kid"] == deployment.meter_jwk["kid"]
    assert len(entry["key_fingerprints"]["key_statement_sha256"]) == 64
    for name in ("key-attestation", "meter-jwks", "statusz"):
        stored = root / entry["files"][name]["path"]
        assert stored.name == name + ".json" and json.loads(stored.read_text()) == files[name]
    verdicts = {c["id"]: c["status"] for c in json.loads((stored.parent / "verifier.json").read_text())["checks"]}
    assert verdicts["keyatt.report_data"] == verdicts["keyatt.keys_origin"] == verdicts["keyatt.keys_match"] == "PASS"
    assert verdicts["keyatt.meter_key"] == verdicts["statusz.consistent"] == "PASS"
    import check_chain
    assert check_chain.main(["--root", str(root)]) == 0
    capsys.readouterr()


def test_recorder_flags_measurements_that_match_no_release(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment)
    first = tmp_path / "a.json"
    first.write_text(json.dumps(deployment.response()))
    run_recorder(root, first, "2030-01-15T12:00:00Z")
    changed = synth.Deployment()  # different compose hash, keys and RTMR3
    changed.events = synth.make_event_log("55" * 32)
    from avlib import eventlog
    changed.rtmrs = eventlog.replay(changed.events)
    second = tmp_path / "b.json"
    second.write_text(json.dumps(changed.response()))
    run_recorder(root, second, "2030-01-15T12:30:00Z")
    capsys.readouterr()
    entries = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert entries[1]["deployment"] is None and entries[1]["measurements_changed"] is True
    assert entries[1]["compose_hash"] == "55" * 32


def test_recorder_records_unreachable_endpoint(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment)
    assert run_recorder(root, tmp_path / "does-not-exist.json", "2030-01-15T12:00:00Z") == record.EXIT_UNREACHABLE
    capsys.readouterr()
    (entry,) = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert entry["verdict"] == "UNREACHABLE" and "files" not in entry and entry["seq"] == 0


def test_recorder_refuses_to_extend_a_broken_chain(tmp_path, deployment, capsys):
    root = make_repo(tmp_path, deployment)
    (root / "history" / "attestations.jsonl").write_text('{"not":"a chain"}\n')
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(deployment.response()))
    assert run_recorder(root, evidence, "2030-01-15T12:00:00Z") == 3
    assert (root / "history" / "attestations.jsonl").read_text() == '{"not":"a chain"}\n'


def test_recorder_without_any_release_is_unmatched(tmp_path, deployment, capsys):
    root = tmp_path / "repo"
    shutil.copytree(PLACEHOLDER_DEPLOYMENTS, root / "deployments")  # placeholder only
    (root / "history").mkdir()
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps(deployment.response()))
    code = run_recorder(root, evidence, "2030-01-15T12:00:00Z")
    capsys.readouterr()
    (entry,) = [json.loads(line) for line in chainlib.read_lines(root / "history" / "attestations.jsonl")]
    assert code == 1 and entry["deployment"] is None and entry["expected_deployment"] is None
    assert "policy.mrtd" in entry["skipped"]


class FakeEndpoint:
    """Stands in for the TLS connection: serves a synthetic deployment's documents by path."""
    busy = 0

    def __init__(self, dep, missing=()):
        self.dep, self.missing, self.spki_seen, self.paths = dep, set(missing), [], []

    def get(self, path):
        from avlib import binding
        self.paths.append(path)
        spki = binding.spki_hash(self.dep.tls_spki)
        self.spki_seen.append(spki)
        name = path.split("?")[0]
        if name in self.missing:
            return 404, b"not found", spki
        if name == "/attestation":
            return 200, json.dumps(self.dep.response(path.split("nonce=")[1])).encode(), spki
        if name == "/.well-known/adverserial-key-attestation":
            if self.busy:
                self.busy -= 1
                return 503, b'{"error":"key attestation is being generated; retry shortly"}', spki
            return 200, json.dumps(self.dep.key_attestation()).encode(), spki
        body = {"/.well-known/hpke-keys": b"\x00\x00\x20" + self.dep.ehbp_pub,
                "/.well-known/adverserial-meter-jwks.json": json.dumps(self.dep.meter_jwks()).encode(),
                "/statusz": json.dumps(self.dep.statusz()).encode()}[name]
        return 200, body, spki


def live_run(monkeypatch, tmp_path, dep, endpoint, at="2030-01-15T12:00:00Z"):
    import verify
    from avlib import checks
    monkeypatch.setattr(verify.fetch, "Endpoint", lambda url: endpoint)
    monkeypatch.setattr(verify.time, "sleep", lambda s: None)
    root = make_repo(tmp_path, dep)
    args = verify.build_parser().parse_args(["https://api.example.test", "--offline", "--at", at,
                                             "--deployment", str(root / "deployments" / "v0.0.0-test")])
    inp, raw = verify.gather(args)
    inp.trust_root = dep.platform.root       # the command line cannot set this; tests can
    return inp, raw, {c["id"]: c["status"] for c in checks.run(inp).checks}


def test_live_fetch_collects_every_endpoint(monkeypatch, tmp_path, deployment):
    endpoint = FakeEndpoint(deployment)
    endpoint.busy = 2                          # the proxy sheds two requests while it generates the quote
    inp, raw, st = live_run(monkeypatch, tmp_path, deployment, endpoint)
    assert set(raw) == {"evidence", "key-attestation", "hpke-keys", "meter-jwks", "statusz"}
    assert endpoint.paths.count("/.well-known/adverserial-key-attestation") == 3 and len(inp.spki_seen) == 7
    skipped = {k for k, v in st.items() if v == "SKIP"}
    assert skipped == {"tdx.collateral_tcb", "keyatt.quote", "gpu.signatures"}        # --offline: no Intel or NVIDIA data
    assert {k for k, v in st.items() if v == "FAIL"} == set()
    assert st["keyatt.keys_match"] == st["keyatt.meter_key"] == st["statusz.consistent"] == st["tls.live_spki"] == "PASS"
    import verify
    saved = verify.save(raw, str(tmp_path / "saved"))
    assert sorted(p.name for p in (tmp_path / "saved").iterdir()) == ["evidence.json", "hpke-keys.bin", "key-attestation.json",
                                                                       "meter-jwks.json", "statusz.json"]
    assert json.loads(open(saved["statusz"]).read())["keys_origin"] == "enclave-generated"


def test_live_fetch_without_the_new_endpoints(monkeypatch, tmp_path, deployment):
    """An older proxy: no key attestation, no meter JWKS, no statusz. Nothing passes silently."""
    endpoint = FakeEndpoint(deployment, missing=["/.well-known/adverserial-key-attestation",
                                                 "/.well-known/adverserial-meter-jwks.json", "/statusz"])
    inp, raw, st = live_run(monkeypatch, tmp_path, deployment, endpoint)
    assert set(raw) == {"evidence", "hpke-keys"} and "HTTP 404" in inp.key_attestation_error
    assert st["keyatt.report_data"] == st["keyatt.keys_origin"] == st["keyatt.meter_key"] == "SKIP"
    assert st["statusz.consistent"] == "N/A"
