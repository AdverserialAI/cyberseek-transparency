import hashlib
import json

import pytest

import synth
from avlib import binding, canonjson, compose, eventlog


def test_canonjson_matches_proxy_rules():
    value = {"b": [1, 2.0, True, None], "a": "é\"\\\n\x01<>&", "c": {"z": 1e21, "y": -0.0, "x": 1.5}}
    assert canonjson.dumps(value) == '{"a":"é\\"\\\\\\n\\u0001<>&","b":[1,2,true,null],"c":{"x":1.5,"y":0,"z":1e+21}}'
    assert canonjson.digest({"a": 1}) == "sha256:" + canonjson.b64url(hashlib.sha256(b'{"a":1}').digest())


def test_canonjson_survives_json_round_trip():
    value = {"n": 1, "s": "x", "l": [1, {"k": None}]}
    assert canonjson.dumps(json.loads(json.dumps(value))) == canonjson.dumps(value)


def test_attestation_report_data_layout():
    nonce, tls, receipt, ehbp = b"n" * 32, b"t" * 91, b"r" * 91, b"e" * 32
    rd = binding.attestation_report_data(nonce, tls, receipt, ehbp)
    assert len(rd) == 64 and rd[32:] == bytes(32)
    assert rd[:32] == hashlib.sha256(b"adverserial-attestation-v2\x00" + nonce + tls + receipt + ehbp).digest()
    assert rd != binding.attestation_report_data(nonce, tls, receipt, b"")


def test_key_attestation_report_data_is_sha512_with_domain():
    statement = b'{"tls_spki_sha256":"sha256:x"}'
    rd = binding.key_attestation_report_data(statement)
    assert rd == hashlib.sha512(b"adverserial-key-attestation-v1\n" + statement).digest() and len(rd) == 64


@pytest.mark.parametrize("bad", ["", "AAAA", "A" * 97, canonjson.b64url(b"x" * 65)])
def test_nonce_validation_rejects(bad):
    with pytest.raises(ValueError):
        binding.validate_nonce(bad)


def test_event_log_replay_and_digest_check():
    events = synth.make_event_log("ab" * 32)
    mrs = eventlog.replay(events)
    assert set(mrs) == {0, 1, 2, 3} and all(len(v) == 96 for v in mrs.values())
    facts = eventlog.runtime_facts(events)
    assert facts["compose-hash"] == "ab" * 32 and facts["app-id"] == synth.APP_ID
    events[-5]["event_payload"] = "00"  # digest no longer matches payload
    with pytest.raises(eventlog.EventLogError):
        eventlog.replay(events)


def test_event_log_rejects_duplicate_and_late_identity_events():
    events = synth.make_event_log("ab" * 32)
    with pytest.raises(eventlog.EventLogError, match="duplicate"):
        eventlog.runtime_facts(events + [synth.runtime_event("compose-hash", b"\x00" * 32)])
    late = [e for e in events if e.get("event") != "app-id"]
    late.insert(-1, synth.runtime_event("app-id", bytes.fromhex(synth.APP_ID)))  # after boot-mr-done
    with pytest.raises(eventlog.EventLogError, match="boot boundary"):
        eventlog.runtime_facts(late)


def test_canonical_app_compose_rule():
    app = {"runner": "docker-compose", "docker_compose_file": "services: {}\n", "bash_script": None,
           "init_script": [], "name": "", "allowed_envs": ["A"], "manifest_version": 2}
    raw = compose.canonical_app_compose(app)
    assert raw == b'{"allowed_envs":["A"],"docker_compose_file":"services: {}\\n","manifest_version":2,"name":"","runner":"docker-compose"}'
    assert compose.app_compose_hash(raw) == (hashlib.sha256(raw).hexdigest(),) * 2
    pretty = json.dumps(app, indent=2).encode()
    published, canonical = compose.app_compose_hash(pretty)
    assert published != canonical == hashlib.sha256(raw).hexdigest()


def test_compose_self_digest_and_images():
    text, _ = synth.make_compose()
    declared, computed = compose.self_digest(text)
    assert declared == computed
    assert compose.self_digest(text + "# changed\n")[0] != compose.self_digest(text + "# changed\n")[1]
    assert compose.unpinned_images(text) == []
    assert compose.unpinned_images(text + "  x:\n    image: nginx:latest\n") == ["nginx:latest"]
    assert compose.sealed_references(compose.load(text)) == set(synth.SEALED)
    with pytest.raises(ValueError):
        compose.self_digest("services: {}\n")


def test_collateral_fetch_calls_the_library_inside_a_running_event_loop(monkeypatch):
    """dcap-qvl's native get_collateral needs a running loop when it is called.

    Found on the first run against the live endpoint: calling it first and
    passing the result to asyncio.run() raised "no running event loop", so
    tdx.collateral_tcb and keyatt.quote were skipped on every live run.
    """
    import asyncio

    from avlib import dcap

    class Collateral:
        def to_json(self):
            return '{"ok":true}'

    class Lib:
        @staticmethod
        def get_collateral(url, raw):
            loop = asyncio.get_running_loop()  # raises RuntimeError outside a loop, like the real one
            future = loop.create_future()
            loop.call_soon(future.set_result, Collateral())
            return future

    monkeypatch.setattr(dcap, "_lib", lambda: Lib)
    assert dcap.fetch_collateral(b"quote", "https://pccs.invalid") == '{"ok":true}'
