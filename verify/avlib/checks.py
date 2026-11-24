"""The verification procedure: an ordered list of independent checks.

Every check ends in one of five states:

  PASS  the property was established
  FAIL  the property is false, or the evidence is malformed
  SKIP  an input was missing (no network, no deployment files ...). A skipped
        check makes the overall verdict INCOMPLETE, never PASS.
  N/A   the property cannot exist in this mode (for example freshness of a
        saved file). It does not change the verdict but is always printed.
  WARN  the evidence is consistent with the published policy, but the policy
        itself switches a protection off. It does not change the verdict
        either: the deployment is what it says it is. It is printed again
        above the verdict and recorded in the history on every run, so that
        nobody reads a PASS as covering the property.

A policy marked pending ("status": "pending", published before the release's
first live attestation) can never yield PASS: `policy.not_pending` is skipped,
so the best possible verdict is INCOMPLETE.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import binding, canonjson, compose, dcap, eventlog, gpu, quote

PASS, FAIL, SKIP, NA, WARN = "PASS", "FAIL", "SKIP", "N/A", "WARN"
GPU_OS_ATTESTATION_DISABLED = "GPU attestation by the OS is disabled by policy (attest_gpu=false)"
DEFAULT_TCB = ("UpToDate",)
MAX_CLOCK_SKEW_S = 300
# The key statement carries no nonce; the proxy reuses one statement for 60 s.
# It must have been issued within this many seconds of the fresh attestation.
KEY_STATEMENT_MAX_AGE_S = 360
KEY_STATEMENT_TYPE = "adverserial-key-attestation/v1"
ENCLAVE_GENERATED = "enclave-generated"


class Skip(Exception):
    pass


class NotApplicable(Exception):
    pass


class Failed(Exception):
    pass


class Warn(Exception):
    pass


@dataclass
class Inputs:
    response: dict                       # {"evidence": ..., "verification_receipt": ...}
    policy: dict
    mode: str = "file"                   # "live" or "file"
    at: dt.datetime | None = None        # verification time (UTC)
    expected_nonce: str | None = None    # the nonce this verifier chose
    live_spki: str | None = None         # SPKI hash of the TLS connection that served the evidence
    spki_seen: list = field(default_factory=list)
    app_compose_raw: bytes | None = None
    docker_compose_text: str | None = None
    collateral_json: str | None = None
    nras_jwks: dict | None = None
    hpke_keys_body: bytes | None = None
    key_attestation: dict | None = None
    key_attestation_collateral_json: str | None = None
    key_attestation_error: str | None = None
    meter_jwks: dict | None = None       # /.well-known/adverserial-meter-jwks.json
    statusz: dict | None = None          # /statusz (unauthenticated, informational)
    # Root of trust for quote signatures. None means the pinned Intel SGX Root
    # CA; the command line cannot change it. Tests pass a throwaway root.
    trust_root: object | None = None


@dataclass
class Result:
    checks: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    mode: str = "file"

    @property
    def verdict(self) -> str:
        states = {c["status"] for c in self.checks}
        if FAIL in states:
            return "FAIL"
        if SKIP in states:
            return "INCOMPLETE"
        return "PASS"

    def to_json(self) -> dict:
        return {"verdict": self.verdict, "mode": self.mode, "checks": self.checks, "summary": self.summary}


def pending_note(policy) -> str | None:
    """Why a policy is pending, or None when it is final. Either marker alone is enough to count as pending."""
    if not isinstance(policy, dict) or not (policy.get("status") == "pending" or "pending" in policy):
        return None
    info = policy.get("pending") if isinstance(policy.get("pending"), dict) else {}
    missing = info.get("missing") if isinstance(info.get("missing"), list) else []
    return "%s (not yet in the policy: %s)" % (info.get("reason") or "the policy is marked pending",
                                               ", ".join(str(m) for m in missing) or "not listed")


def _eq(name, got, want):
    if not want:
        raise Skip("the policy does not pin %s" % name)
    if got != want:
        raise Failed("%s is %s, policy expects %s" % (name, got, want))
    return "%s = %s" % (name, got)


def run(inp: Inputs) -> Result:
    res = Result(mode=inp.mode)
    at = inp.at or dt.datetime.now(dt.timezone.utc)
    ev = inp.response.get("evidence") if isinstance(inp.response, dict) else None
    policy, tdx_policy = inp.policy, inp.policy.get("tdx", {})
    vcfg = policy.get("verifier", {})
    state: dict = {}

    def check(cid, title, fn):
        try:
            detail, status = fn(), PASS
        except Skip as exc:
            detail, status = str(exc), SKIP
        except NotApplicable as exc:
            detail, status = str(exc), NA
        except Warn as exc:
            detail, status = str(exc), WARN
        except (Failed, quote.QuoteError, eventlog.EventLogError, gpu.GPUError, dcap.DcapUnavailable,
                compose.ComposeViolation) as exc:
            detail, status = str(exc), SKIP if isinstance(exc, dcap.DcapUnavailable) else FAIL
        except Exception as exc:  # malformed evidence must fail closed, never crash
            detail, status = "%s: %s" % (type(exc).__name__, exc), FAIL
        res.checks.append({"id": cid, "title": title, "status": status, "detail": detail or ""})
        return status == PASS

    # ---- is the policy final? ---------------------------------------------
    def c_not_pending():
        note = pending_note(policy)
        if note:
            res.summary["policy_pending"] = note
            raise Skip("PENDING POLICY: %s. This release has not been verified live by its publisher yet, so no PASS "
                       "is possible; the checks below show what already holds." % note)
        return "the policy is not marked pending"

    check("policy.not_pending", "The policy is final, not waiting for a first live attestation", c_not_pending)

    # ---- evidence shape ---------------------------------------------------
    def c_format():
        if not isinstance(ev, dict):
            raise Failed("response has no evidence object")
        for k in ("nonce", "tdx_quote", "tdx_event_log", "tls_spki_der", "tls_spki_sha256", "receipt_pubkey_jwk", "workload"):
            if not ev.get(k):
                raise Failed("evidence is missing %s" % k)
        if ev.get("dev"):
            raise Failed("evidence is flagged dev=true (synthetic, proves nothing)")
        state["quote"] = quote.parse(bytes.fromhex(ev["tdx_quote"]))
        state["events"] = eventlog.load(ev["tdx_event_log"])
        state["issued_at"] = gpu.parse_time(ev["issued_at"])
        return "TDX quote v4, %d bytes; %d event-log entries" % (len(state["quote"].raw), len(state["events"]))

    if not check("evidence.format", "Evidence is well formed and not development-mode", c_format):
        res.summary = dict(res.summary, error="evidence could not be parsed")
        return res
    q, events = state["quote"], state["events"]

    # ---- Intel TDX quote --------------------------------------------------
    def c_sig():
        info = quote.verify_signature_chain(q, at, inp.trust_root)
        return "PCK chain -> %s -> pinned Intel SGX Root CA (%s...)" % (info["pck_issuer"], info["root_sha256"][:16])

    check("tdx.quote_signature", "Quote is signed by a key certified up to Intel's root CA", c_sig)

    def c_tcb():
        if not inp.collateral_json:
            raise Skip("no Intel collateral (offline and no --collateral file); revocation and TCB level not evaluated")
        try:
            out = dcap.verify(q.raw, inp.collateral_json, int(at.timestamp()))
        except ValueError as exc:
            raise Failed("dcap-qvl rejected the quote at %s: %s (old evidence? pass --at with the recorded time)"
                         % (at.strftime("%Y-%m-%dT%H:%M:%SZ"), exc)) from None
        rep = out["report"]
        for ours, theirs in (("mrtd", "mr_td"), ("rtmr0", "rt_mr0"), ("rtmr1", "rt_mr1"), ("rtmr2", "rt_mr2"),
                             ("rtmr3", "rt_mr3"), ("report_data", "report_data")):
            if rep.get(theirs, "").lower() != q.hex(ours):
                raise Failed("dcap-qvl and the built-in parser disagree on %s" % ours)
        accepted = tuple(vcfg.get("accepted_tcb_status") or DEFAULT_TCB)
        res.summary["tcb_status"], res.summary["advisory_ids"] = out["status"], out["advisory_ids"]
        if out["status"] not in accepted:
            raise Failed("TCB status %s (advisories: %s); accepted: %s"
                         % (out["status"], ", ".join(out["advisory_ids"]) or "none", ", ".join(accepted)))
        return "dcap-qvl: TCB status %s, advisories: %s" % (out["status"], ", ".join(out["advisory_ids"]) or "none")

    check("tdx.collateral_tcb", "Intel collateral: not revoked, platform TCB level acceptable", c_tcb)

    def c_debug():
        if q.debug:
            raise Failed("the TD has the DEBUG attribute set; its memory is readable by the host")
        return "td_attributes = %s (debug bit clear)" % q.hex("td_attributes")

    check("tdx.not_debug", "The VM is not a debug TD", c_debug)

    # ---- freshness and key binding ---------------------------------------
    def c_nonce():
        binding.validate_nonce(ev["nonce"])
        if inp.expected_nonce is None:
            raise NotApplicable("saved evidence: it echoes nonce %s..., but nobody can prove from a file when it was produced"
                                % ev["nonce"][:12])
        if ev["nonce"] != inp.expected_nonce:
            raise Failed("evidence echoes a different nonce than the one this verifier sent")
        return "evidence echoes the %d-byte random nonce chosen for this run" % len(binding.validate_nonce(ev["nonce"]))

    check("binding.nonce", "Evidence answers this verifier's fresh random nonce", c_nonce)

    def c_fresh():
        if inp.mode != "live":
            raise NotApplicable("saved evidence issued at %s; verified as of %s" % (ev["issued_at"], at.strftime("%Y-%m-%dT%H:%M:%SZ")))
        skew = abs((at - state["issued_at"]).total_seconds())
        if skew > MAX_CLOCK_SKEW_S:
            raise Failed("issued_at differs from local time by %ds" % skew)
        return "issued_at %s is within %ds of local time" % (ev["issued_at"], MAX_CLOCK_SKEW_S)

    check("binding.freshness", "Evidence timestamp is current", c_fresh)

    def c_report_data():
        tls_spki = canonjson.b64url_decode(ev["tls_spki_der"])
        serialization.load_der_public_key(tls_spki)  # must be a real SubjectPublicKeyInfo
        if binding.spki_hash(tls_spki) != ev["tls_spki_sha256"]:
            raise Failed("tls_spki_sha256 is not the hash of tls_spki_der")
        receipt = binding.receipt_spki_der(ev["receipt_pubkey_jwk"])
        ehbp = ev.get("ehbp") or {}
        ehbp_pub = canonjson.b64url_decode(ehbp["public_key"]) if ehbp.get("public_key") else b""
        if len(receipt) != binding.P256_SPKI_LEN or len(ehbp_pub) not in (0, binding.X25519_LEN):
            raise Failed("unexpected key encoding lengths")
        if ehbp_pub and ehbp.get("public_key_sha256") != binding.spki_hash(ehbp_pub):
            raise Failed("ehbp.public_key_sha256 is not the hash of ehbp.public_key")
        expected = binding.attestation_report_data(binding.validate_nonce(ev["nonce"]), tls_spki, receipt, ehbp_pub)
        if q.fields["report_data"] != expected:
            raise Failed("quote report_data does not bind this nonce, TLS key, receipt key and EHBP key")
        state["tls_spki"], state["receipt_spki"], state["ehbp_pub"] = tls_spki, receipt, ehbp_pub
        return ("report_data = SHA-256(domain || nonce || TLS SPKI || receipt SPKI || EHBP key) || 0^32 matches; EHBP key %s"
                % ("bound" if ehbp_pub else "ABSENT"))

    check("binding.report_data", "Quote binds the nonce, TLS key, receipt key and HPKE (EHBP) key", c_report_data)

    def c_ehbp_required():
        if not state.get("ehbp_pub"):
            raise Failed("no EHBP receiver key is attested; request bodies would only be protected by TLS")
        return "X25519 receiver key %s" % ev["ehbp"]["public_key_sha256"]

    check("binding.ehbp_key", "An HPKE receiver key for encrypted request bodies is attested", c_ehbp_required)

    # ---- event log --------------------------------------------------------
    def c_replay():
        mrs = eventlog.replay(events)
        bad = [i for i in range(4) if mrs[i] != q.hex("rtmr%d" % i)]
        if 3 in bad:
            raise Failed("replayed RTMR3 does not match the quote")
        if bad:
            raise Failed("replayed RTMR%s do not match the quote" % ",".join(map(str, bad)))
        return "RTMR0-3 recomputed from %d events equal the quoted values" % len(events)

    check("eventlog.replay", "Event log replays to the RTMR values in the quote", c_replay)

    def c_order():
        state["facts"] = eventlog.runtime_facts(events)
        extra = state["facts"]["_events_after_system_ready"]
        optional = [n for n in eventlog.OPTIONAL_BEFORE_BOOT_DONE + eventlog.OPTIONAL_BEFORE_READY if n in state["facts"]]
        return "app-id, compose-hash, instance-id precede boot-mr-done; os-image-hash, key-provider precede system-ready" + (
            "; also unique and inside the boundary: %s" % ", ".join(optional) if optional else "") + (
            "; events after system-ready: %s" % ", ".join(extra) if extra else "")

    facts_ok = check("eventlog.boot_order", "Launch identity events are unique and inside the boot boundary", c_order)
    facts = state.get("facts", {}) if facts_ok else {}

    # ---- policy -----------------------------------------------------------
    for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2"):
        check("policy." + name, "%s matches the policy" % name.upper(),
              lambda name=name: _eq(name, q.hex(name), tdx_policy.get(name)))
    for event, fieldname in (("os-image-hash", "os_image_hash"), ("app-id", "app_id"), ("compose-hash", "compose_hash")):
        def c_fact(event=event, fieldname=fieldname):
            if event not in facts:
                raise Failed("no trusted %s event" % event)
            return _eq(fieldname, facts[event], tdx_policy.get(fieldname))
        check("policy." + fieldname, "%s matches the policy" % fieldname, c_fact)

    def c_gpu_policy_pin():
        measured, pinned = facts.get("gpu-policy-hash"), tdx_policy.get("gpu_policy_hash")
        if not facts_ok:
            raise Failed("no trusted event log to read gpu-policy-hash from")
        if measured is None and not pinned:
            raise NotApplicable("this OS image records no gpu-policy-hash event (dstack 0.5.x) and the policy pins none")
        if measured is None:
            raise Failed("the policy pins gpu_policy_hash %s, but the event log has no gpu-policy-hash event" % pinned)
        if not pinned:
            raise Skip("the OS measured gpu-policy-hash %s, but the policy does not pin tdx.gpu_policy_hash" % measured)
        return _eq("gpu_policy_hash", measured, pinned)

    check("policy.gpu_policy_hash", "gpu_policy_hash matches the policy", c_gpu_policy_pin)

    workload = ev.get("workload", {})

    def c_workload():
        pairs = (("compose_digest", "deployment_configuration_digest"), ("model_digest", "model_artifact_digest"),
                 ("proxy_version", "proxy_version"), ("policy_id", "policy_id"), ("model_id", "model_id"))
        pinned = [(w, p) for w, p in pairs if policy.get(p)]
        if not pinned:
            raise Skip("the policy pins no workload fields")
        for w, p in pinned:
            if workload.get(w) != policy[p]:
                raise Failed("workload.%s is %s, policy expects %s" % (w, workload.get(w), policy[p]))
        return "self-reported (not hardware-measured) fields match: " + ", ".join(w for w, _ in pinned)

    check("policy.workload", "Proxy's self-reported workload fields match the policy", c_workload)

    # ---- receipt ----------------------------------------------------------
    def c_receipt():
        jws = inp.response.get("verification_receipt")
        if not isinstance(jws, str) or jws.count(".") != 2:
            raise Failed("no verification receipt")
        h, p, s = jws.split(".")
        header, claims, sig = json.loads(canonjson.b64url_decode(h)), json.loads(canonjson.b64url_decode(p)), canonjson.b64url_decode(s)
        jwk = ev["receipt_pubkey_jwk"]
        kid = binding.jwk_thumbprint(jwk)
        if header.get("alg") != "ES256" or header.get("kid") != kid or len(sig) != 64:
            raise Failed("receipt is not an ES256 JWS under the attested receipt key")
        key = serialization.load_der_public_key(binding.receipt_spki_der(jwk))
        try:
            key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                       (h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise Failed("receipt signature is invalid") from None
        if claims.get("evidence_sha256") != canonjson.digest(ev):
            raise Failed("receipt does not commit to this evidence object")
        if claims.get("nonce") != ev["nonce"]:
            raise Failed("receipt nonce differs from evidence nonce")
        pinned = policy.get("receipt_keys")
        note = ""
        if pinned:
            if kid not in pinned:
                raise Failed("receipt key %s is not one of the keys pinned by the policy" % kid)
            note = "; key is pinned by the policy"
        return "ES256 receipt by attested key %s commits to the canonical evidence digest%s" % (kid, note)

    check("receipt.signature", "Signed receipt matches the attested receipt key and this evidence", c_receipt)

    # ---- deployment files -------------------------------------------------
    def c_app_compose():
        if inp.app_compose_raw is None:
            raise Skip("no app-compose.json supplied (--deployment or --app-compose)")
        as_published, canonical = compose.app_compose_hash(inp.app_compose_raw)
        measured = facts.get("compose-hash")
        if not measured:
            raise Failed("no trusted compose-hash event to compare with")
        if as_published == measured:
            return "SHA-256(app-compose.json) = %s = measured compose-hash" % measured
        if canonical == measured:
            raise Failed("app-compose.json hashes to the measured value only after canonicalisation; publish the canonical bytes")
        raise Failed("SHA-256(app-compose.json) = %s, measured compose-hash = %s" % (as_published, measured))

    app_ok = check("compose.app_compose_hash", "Published app-compose.json hashes to the measured compose-hash", c_app_compose)
    app = json.loads(inp.app_compose_raw) if app_ok else None

    def need_compose():
        if inp.docker_compose_text is None:
            raise Skip("no docker-compose.yml supplied (--deployment or --docker-compose)")
        return inp.docker_compose_text

    def c_docker_compose():
        text = need_compose()
        if app is None:
            raise Skip("needs a verified app-compose.json")
        if app.get("docker_compose_file") != text:
            raise Failed("docker-compose.yml is not byte-identical to docker_compose_file inside app-compose.json")
        return "docker-compose.yml is byte-identical to the measured docker_compose_file (%d bytes)" % len(text.encode())

    dc_ok = check("compose.docker_compose", "Published docker-compose.yml is the one inside the measured manifest", c_docker_compose)

    def c_self_digest():
        declared, computed = compose.self_digest(need_compose())
        if declared != computed:
            raise Failed("COMPOSE_DIGEST in the compose is %s but recomputes to %s" % (declared, computed))
        if workload.get("compose_digest") != computed:
            raise Failed("proxy reports compose_digest %s, published compose recomputes to %s" % (workload.get("compose_digest"), computed))
        return "COMPOSE_DIGEST recomputes to %s and equals the value the proxy reports" % computed

    check("compose.self_digest", "COMPOSE_DIGEST recomputes from the published compose", c_self_digest)

    def need_doc():
        if "compose_doc" not in state:
            state["compose_doc"] = compose.load(need_compose())
        return state["compose_doc"]

    proxy_service = vcfg.get("proxy_service") or compose.DEFAULT_PROXY_SERVICE
    inference_service = vcfg.get("inference_service") or compose.DEFAULT_INFERENCE_SERVICE

    def c_images():
        refs = compose.check_images(need_doc())
        want = [(k, policy[k]) for k in ("runtime_image_digest", "proxy_image_digest") if policy.get(k)]
        for k, digest in want:
            if not any(r.endswith("@" + digest) for r in refs):
                raise Failed("policy %s %s is not an image in the compose" % (k, digest))
        state["images"] = refs
        return "%d services, %d distinct images, all pinned by sha256 digest%s%s" % (
            len(need_doc()["services"]), len(refs), "; policy digests present: " + ", ".join(k for k, _ in want) if want else "",
            "" if dc_ok else " (WARNING: compose not tied to the measured manifest)")

    check("compose.images_pinned", "Every container image is pinned by digest", c_images)

    def c_unmeasured():
        doc = need_doc()
        if app is None:
            raise Skip("needs a verified app-compose.json")
        res.summary["allowed_envs"] = sorted(app.get("allowed_envs") or [])
        permitted = vcfg.get("allowed_envs")
        if permitted is None:
            raise Skip("policy has no verifier.allowed_envs list; operator-settable variables: %s"
                       % (", ".join(res.summary["allowed_envs"]) or "none"))
        return compose.check_sealed_envs(doc, app.get("allowed_envs"), permitted)

    check("compose.unmeasured_inputs", "Operator-supplied environment variables are exactly the policy's list", c_unmeasured)

    def c_keys_in_enclave():
        return compose.check_keys_in_enclave(
            need_doc(), need_compose(), (app or {}).get("allowed_envs"), proxy_service, vcfg.get("operator_key_envs"),
            vcfg.get("enclave_key_proxy_digests"), policy.get("proxy_image_digest"))

    check("compose.keys_in_enclave", "The compose makes the proxy generate its keys inside the VM", c_keys_in_enclave)
    check("compose.inference_isolated", "The model server is reachable only from the proxy, on an internal network",
          lambda: compose.check_inference_isolated(need_doc(), inference_service, proxy_service))
    check("compose.single_ingress", "Only the proxy publishes a port",
          lambda: compose.check_single_ingress(need_doc(), proxy_service))

    # ---- live TLS and key endpoints --------------------------------------
    def c_tls():
        if inp.mode != "live" or not inp.live_spki:
            raise NotApplicable("saved evidence: there is no live TLS connection to compare (attested SPKI %s)" % ev["tls_spki_sha256"])
        seen = set(inp.spki_seen or [inp.live_spki])
        if seen != {ev["tls_spki_sha256"]}:
            raise Failed("live certificate SPKI %s differs from attested %s" % (", ".join(sorted(seen)), ev["tls_spki_sha256"]))
        return "all %d connections presented SPKI %s, the attested TLS key" % (len(inp.spki_seen) or 1, ev["tls_spki_sha256"])

    check("tls.live_spki", "The live TLS certificate uses the attested TLS key", c_tls)

    def c_tls_policy():
        if not policy.get("tls_spki_sha256"):
            raise NotApplicable("the policy does not pin a TLS key (expected when keys are generated per boot)")
        return _eq("tls_spki_sha256", ev["tls_spki_sha256"], policy["tls_spki_sha256"])

    check("policy.tls_spki", "Attested TLS key matches the policy pin", c_tls_policy)

    def c_hpke():
        if inp.mode != "live":
            raise NotApplicable("saved evidence: /.well-known/hpke-keys was not fetched")
        if inp.hpke_keys_body is None:
            raise Skip("could not fetch /.well-known/hpke-keys")
        want = canonjson.b64url_decode(ev["ehbp"]["key_config"])
        if inp.hpke_keys_body != want and state["ehbp_pub"] not in inp.hpke_keys_body:
            raise Failed("the served HPKE key configuration does not contain the attested EHBP key")
        return "served key configuration carries the attested X25519 key"

    check("keys.hpke_endpoint", "/.well-known/hpke-keys serves the attested HPKE key", c_hpke)

    # ---- key attestation ---------------------------------------------------
    # GET /.well-known/adverserial-key-attestation ->
    #   {"statement": "<canonical JSON string>", "quote": "<hex>", "event_log": ...}
    # attest-proxy internal/server/status.go; the steps follow its README recipe.
    ka = inp.key_attestation

    def need_ka():
        if ka is None:
            if inp.key_attestation_error:
                raise Skip(inp.key_attestation_error)
            if inp.mode != "live":
                raise Skip("no key-attestation document supplied (--key-attestation-file)")
            raise Skip("endpoint did not serve /.well-known/adverserial-key-attestation")
        return ka

    def c_ka_report_data():
        doc = need_ka()
        if not isinstance(doc, dict) or not isinstance(doc.get("statement"), str) or not isinstance(doc.get("quote"), str):
            raise Failed('key attestation is not {"statement": "<string>", "quote": "<hex>", ...}')
        raw = doc["statement"].encode("utf-8")  # exactly as served: never re-serialised before hashing
        kq = quote.parse(bytes.fromhex(doc["quote"]))
        if kq.fields["report_data"] != binding.key_attestation_report_data(raw):
            raise Failed('quote report_data is not SHA-512("adverserial-key-attestation-v1\\n" || statement)')
        parsed = json.loads(doc["statement"])
        if not isinstance(parsed, dict) or canonjson.dumps(parsed).encode("utf-8") != raw:
            raise Failed("statement is not canonical JSON, so its meaning could differ between parsers")
        state["ka_quote"], state["ka_statement"] = kq, parsed
        res.summary["key_statement_sha256"] = hashlib.sha256(raw).hexdigest()
        return "all 64 bytes of report_data = SHA-512(domain || statement); statement fields: %s" % ", ".join(sorted(parsed))

    ka_ok = check("keyatt.report_data", "Key attestation quote commits to the published key statement", c_ka_report_data)
    st = state.get("ka_statement") or {}

    def need_statement():
        if not ka_ok:
            raise Skip("needs a key attestation whose quote commits to its statement")
        return st

    def c_ka_quote():
        need_statement()
        kq = state["ka_quote"]
        quote.verify_signature_chain(kq, at, inp.trust_root)
        if kq.debug:
            raise Failed("key attestation comes from a debug TD")
        for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
            if kq.fields[name] != q.fields[name]:
                raise Failed("key attestation %s differs from the fresh quote: not the same measured VM" % name)
        note = ""
        if ka.get("event_log") is not None:
            kevents = eventlog.load(ka["event_log"])
            mrs = eventlog.replay(kevents)
            if any(mrs[i] != kq.hex("rtmr%d" % i) for i in range(4)):
                raise Failed("the key attestation's event log does not replay to its quote")
            if eventlog.runtime_facts(kevents).get("compose-hash") != facts.get("compose-hash"):
                raise Failed("the key attestation's event log records a different compose-hash")
            note = "; its own event log replays to the same compose-hash"
        collateral = inp.key_attestation_collateral_json or inp.collateral_json
        if not collateral:
            raise Skip("signature chain and measurements match the fresh quote, but no Intel collateral to evaluate TCB")
        try:
            out = dcap.verify(kq.raw, collateral, int(at.timestamp()))
        except ValueError as exc:
            raise Failed("dcap-qvl rejected the key-attestation quote: %s" % exc) from None
        if out["report"].get("report_data", "").lower() != kq.hex("report_data"):
            raise Failed("dcap-qvl and the built-in parser disagree on report_data")
        if out["status"] not in tuple(vcfg.get("accepted_tcb_status") or DEFAULT_TCB):
            raise Failed("key attestation TCB status %s" % out["status"])
        return "signed up to Intel's root, TCB %s, not debug, MRTD and RTMR0-3 identical to the fresh quote%s" % (out["status"], note)

    check("keyatt.quote", "Key attestation quote is genuine and from the same measured VM", c_ka_quote)

    def c_ka_statement():
        need_statement()
        if st.get("type") != KEY_STATEMENT_TYPE:
            raise Failed("statement type is %r, expected %s" % (st.get("type"), KEY_STATEMENT_TYPE))
        if "dev" in st:
            raise Failed("statement is flagged dev (synthetic, proves nothing)")
        issued = gpu.parse_time(st["issued_at"])
        gap = abs((issued - state["issued_at"]).total_seconds())
        if gap > KEY_STATEMENT_MAX_AGE_S:
            raise Failed("statement issued_at %s is %ds away from the fresh attestation (limit %ds)"
                         % (st["issued_at"], gap, KEY_STATEMENT_MAX_AGE_S))
        if st.get("proxy_version") != workload.get("proxy_version"):
            raise Failed("statement proxy_version %s differs from the fresh attestation's %s"
                         % (st.get("proxy_version"), workload.get("proxy_version")))
        return "type %s, proxy %s, issued %s (%ds from the fresh attestation)" % (st["type"], st["proxy_version"], st["issued_at"], gap)

    check("keyatt.statement", "Key statement is the expected kind, current and not development-mode", c_ka_statement)

    def c_ka_origin():
        need_statement()
        if st.get("keys_origin") != ENCLAVE_GENERATED:
            raise Failed("keys_origin is %r: the proxy says its keys were NOT generated inside the VM" % st.get("keys_origin"))
        return "keys_origin = %s, stated inside a hardware-signed quote by the measured proxy" % ENCLAVE_GENERATED

    check("keyatt.keys_origin", "The measured proxy states that it generated its keys inside the VM", c_ka_origin)

    def c_ka_keys():
        need_statement()
        jwk, sjwk = ev["receipt_pubkey_jwk"], st.get("receipt_pubkey_jwk")
        if not isinstance(sjwk, dict) or "d" in sjwk or any(sjwk.get(k) != jwk.get(k) for k in ("kty", "crv", "x", "y")):
            raise Failed("statement receipt key is not the receipt key of the fresh attestation")
        kid = binding.jwk_thumbprint(jwk)
        if sjwk.get("kid") != kid:
            raise Failed("statement receipt key id is not the RFC 7638 thumbprint of the key")
        notes = ["receipt key %s" % kid]
        pinned = policy.get("receipt_keys")
        if pinned and kid not in pinned:
            raise Failed("receipt key %s is not one of the keys pinned by the policy" % kid)
        notes.append("pinned by the policy" if pinned else "policy pins no receipt key")
        ehbp = ev.get("ehbp") or {}
        if not st.get("ehbp_public_key") or st["ehbp_public_key"] != ehbp.get("public_key"):
            raise Failed("statement EHBP key is not the HPKE key of the fresh attestation")
        if st.get("ehbp_public_key_sha256") != binding.spki_hash(canonjson.b64url_decode(st["ehbp_public_key"])):
            raise Failed("statement ehbp_public_key_sha256 is not the hash of ehbp_public_key")
        notes.append("EHBP key %s" % st["ehbp_public_key_sha256"])
        if st.get("tls_spki_sha256") != ev["tls_spki_sha256"]:
            raise Failed("statement TLS key %s is not the TLS key of the fresh attestation %s" % (st.get("tls_spki_sha256"), ev["tls_spki_sha256"]))
        seen = set(inp.spki_seen or ([inp.live_spki] if inp.live_spki else []))
        if seen and seen != {st["tls_spki_sha256"]}:
            raise Failed("statement TLS key %s is not the key of the live certificate (%s)" % (st["tls_spki_sha256"], ", ".join(sorted(seen))))
        notes.append("TLS key %s%s" % (st["tls_spki_sha256"], " = live certificate" if seen else " (no live connection to compare)"))
        if policy.get("tls_spki_sha256"):
            if st["tls_spki_sha256"] != policy["tls_spki_sha256"]:
                raise Failed("statement TLS key is not the one pinned by the policy")
            notes.append("TLS key pinned by the policy")
        return "statement lists the keys in use: " + "; ".join(notes)

    check("keyatt.keys_match", "Key statement lists the receipt, HPKE and TLS keys actually in use", c_ka_keys)

    def c_ka_meter():
        need_statement()
        mjwk = st.get("meter_pubkey_jwk")
        if not isinstance(mjwk, dict) or mjwk.get("kty") != "OKP" or mjwk.get("crv") != "Ed25519" or "d" in mjwk:
            raise Failed("statement carries no Ed25519 public meter key")
        x = canonjson.b64url_decode(mjwk.get("x") or "")
        if len(x) != 32 or mjwk.get("kid") != canonjson.b64url(hashlib.sha256(x).digest()):
            raise Failed("statement meter key id is not the SHA-256 of the 32-byte public key")
        res.summary["meter_kid"] = mjwk["kid"]
        if inp.meter_jwks is None:
            if inp.mode != "live":
                raise NotApplicable("saved evidence: /.well-known/adverserial-meter-jwks.json was not supplied (--meter-jwks-file); attested meter key %s" % mjwk["kid"])
            raise Skip("could not fetch /.well-known/adverserial-meter-jwks.json; attested meter key %s" % mjwk["kid"])
        if not isinstance(inp.meter_jwks, dict) or inp.meter_jwks.get("keys") != [mjwk]:
            raise Failed("the served meter JWKS is not exactly the meter key in the quote-bound statement")
        return "served JWKS holds exactly the attested Ed25519 meter key %s" % mjwk["kid"]

    check("keyatt.meter_key", "The published billing (meter) key is the one in the key statement", c_ka_meter)

    # ---- /statusz (unauthenticated; informational) -------------------------
    def c_statusz():
        sz = inp.statusz
        if not isinstance(sz, dict):
            raise NotApplicable("informational: /statusz was not fetched; nothing depends on it")
        shown = {k: sz.get(k) for k in ("version", "keys_origin", "receipt_kid", "ehbp_public_key_sha256")}
        res.summary["statusz"] = shown
        expected = {"version": workload.get("proxy_version"), "receipt_kid": binding.jwk_thumbprint(ev["receipt_pubkey_jwk"]),
                    "ehbp_public_key_sha256": (ev.get("ehbp") or {}).get("public_key_sha256"),
                    "keys_origin": st.get("keys_origin") if ka_ok else ENCLAVE_GENERATED}
        bad = ["%s is %r, attested %r" % (k, shown[k], v) for k, v in expected.items() if shown[k] != v]
        if bad:
            raise Failed("/statusz contradicts the attestation: " + "; ".join(bad))
        return "informational, agrees with the attestation: version %s, keys_origin %s, receipt_kid %s, ehbp_public_key_sha256 %s" % (
            shown["version"], shown["keys_origin"], shown["receipt_kid"], shown["ehbp_public_key_sha256"])

    check("statusz.consistent", "/statusz (unauthenticated) agrees with the attested values", c_statusz)

    # ---- NVIDIA GPUs ------------------------------------------------------
    def c_gpu():
        minimum = int(policy.get("allowed_runtime", {}).get("minimum_gpu_count", 1))
        max_age = int(policy.get("freshness", {}).get("gpu_evidence_max_age_seconds", 1800))
        info = gpu.check_structure(ev, minimum, max_age, state["issued_at"])
        state["gpu"] = info
        res.summary["gpu"] = {k: info[k] for k in ("gpu_count", "hwmodels", "generated_at", "nonce_source")}
        return "%d GPUs (%s): NRAS overall result true, per-GPU measres=success, secboot, debug disabled; evidence %s" % (
            info["gpu_count"], ", ".join(info["hwmodels"]), info["generated_at"])

    gpu_ok = check("gpu.evidence", "NVIDIA attestation tokens are consistent and cover enough GPUs", c_gpu)

    def c_gpu_sig():
        if not gpu_ok:
            raise Skip("needs consistent GPU evidence")
        if not inp.nras_jwks:
            raise Skip("NVIDIA signing keys unavailable (offline and no --nras-jwks file); token signatures not verified")
        try:
            n = gpu.check_signatures(state["gpu"]["tokens"], inp.nras_jwks)
        except gpu.GPUKeyUnknown as exc:
            if inp.mode == "live":
                raise
            # NVIDIA rotates signing keys; old tokens need the key set saved with them.
            raise Skip("%s (NVIDIA rotates keys: use the nras-jwks.json recorded with this evidence)" % exc) from None
        return "%d tokens carry valid ES384 signatures from keys published at %s" % (n, gpu.NRAS_ORIGIN)

    check("gpu.signatures", "NVIDIA tokens are signed by NVIDIA's attestation service", c_gpu_sig)

    def c_gpu_binding():
        raise NotApplicable("NOT VERIFIED BY DESIGN: the GPU evidence is not bound to the TDX quote or to your nonce "
                            "(nonce source: %s). It is relayed by the measured collector and proxy." % (ev.get("gpu_evidence") or {}).get("nonce_source"))

    check("gpu.bound_to_vm", "GPU evidence is cryptographically bound to this VM", c_gpu_binding)

    # ---- did the OS attest the GPUs before releasing keys? ------------------
    # dstack 0.6.x measures the manifest's GPU policy ('gpu-policy-hash') and,
    # unless that policy says "attest_gpu": false, attests every attached GPU
    # and requires its Confidential Computing mode to be on before the VM gets
    # its keys ('gpu-attestation'). dstack 0.5.x has neither event.
    def c_gpu_os():
        if not facts_ok:
            raise Failed("no trusted event log to read the GPU policy from")
        measured, attested = facts.get("gpu-policy-hash"), "gpu-attestation" in facts
        if measured is None:
            if attested:
                raise Failed("the event log has a gpu-attestation event but no gpu-policy-hash event")
            res.summary["gpu_os_attestation"] = "not-supported-by-os"
            raise NotApplicable("this OS image (dstack 0.5.x event log) does not attest GPUs at boot; nothing in the measured "
                                "boot chain verifies the GPUs, see gpu.evidence for the application-level check")
        declared = None
        if app is not None:
            declared = compose.gpu_policy(app)
            recomputed = compose.gpu_policy_hash(declared)
            if recomputed != measured:
                raise Failed("measured gpu-policy-hash %s is not SHA-256(JCS(requirements.gpu_policy)) = %s of the published manifest"
                             % (measured, recomputed))
        elif measured == compose.GPU_ATTESTATION_OFF_HASH:
            declared = dict(compose.GPU_ATTESTATION_OFF)
        if declared is None:
            raise Skip("the OS measured gpu-policy-hash %s; the published app-compose.json is needed to read that policy" % measured)
        if declared.get("attest_gpu", True) is False:
            if attested:
                raise Failed("the measured GPU policy says attest_gpu=false, yet the event log has a gpu-attestation event")
            res.summary["gpu_os_attestation"] = "disabled-by-policy"
            raise Warn("%s. The measured manifest carries requirements.gpu_policy = %s (gpu-policy-hash %s) and the event log has "
                       "no gpu-attestation event: the OS released the VM's keys without attesting the GPUs or checking their "
                       "confidential mode. Nothing in the measured boot chain verifies the GPUs' protected mode. What is "
                       "checked instead is gpu.evidence and gpu.signatures (NVIDIA's remote attestation, not bound to the TDX quote)."
                       % (GPU_OS_ATTESTATION_DISABLED, canonjson.dumps(declared), measured))
        if not attested:
            raise Failed("the measured GPU policy requires attestation by the OS, but the event log has no gpu-attestation event")
        res.summary["gpu_os_attestation"] = "attested-at-boot"
        return ("the OS attested the GPUs before releasing keys: gpu-policy-hash %s, gpu-attestation event %s..."
                % (measured, facts["gpu-attestation"][:16]))

    check("gpu.os_attestation", "The OS attested the GPUs and their confidential mode before releasing keys", c_gpu_os)

    # ---- summary ----------------------------------------------------------
    jwk = ev["receipt_pubkey_jwk"]
    res.summary.update({
        "issued_at": ev.get("issued_at"),
        "nonce": ev.get("nonce"),
        "measurements": {n: q.hex(n) for n in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")},
        "app_id": facts.get("app-id"),
        "compose_hash": facts.get("compose-hash"),
        "os_image_hash": facts.get("os-image-hash"),
        "gpu_policy_hash": facts.get("gpu-policy-hash"),
        "instance_id": facts.get("instance-id"),
        "key_provider_sha256": hashlib.sha256(bytes.fromhex(facts["key-provider"])).hexdigest() if facts.get("key-provider") else None,
        "compose_digest": workload.get("compose_digest"),
        "model_digest": workload.get("model_digest"),
        "proxy_version": workload.get("proxy_version"),
        "tls_spki_sha256": ev.get("tls_spki_sha256"),
        "live_tls_spki_sha256": inp.live_spki,
        "keys": {
            "receipt_kid": binding.jwk_thumbprint(jwk) if isinstance(jwk, dict) and "x" in jwk else None,
            "ehbp_public_key_sha256": (ev.get("ehbp") or {}).get("public_key_sha256"),
            "keys_origin": (state.get("ka_statement") or {}).get("keys_origin"),
            "meter_kid": res.summary.get("meter_kid"),
            "key_statement": state.get("ka_statement"),
        },
        "images": state.get("images"),
        "verified_at": at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "warnings": [{"id": c["id"], "detail": c["detail"]} for c in res.checks if c["status"] == WARN],
    })
    return res
