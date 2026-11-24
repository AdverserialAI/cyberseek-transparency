#!/usr/bin/env python3
"""Independent verifier for the Adverserial confidential-inference deployment.

    python verify/verify.py https://api.adverserial.ai --deployment deployments/<release>
    python verify/verify.py --file evidence.json --policy policy.json [--collateral c.json] [--at TIME]

Exit status: 0 = PASS, 1 = FAIL, 2 = INCOMPLETE (a check was skipped), 3 = usage or fetch error.

A WARN line does not change the exit status: the evidence matches the published
policy, but the policy switches a protection off (today: `gpu.os_attestation`).
It is printed in the list and again above the verdict.

A release whose policy.json is marked "status": "pending" was published before
its first live attestation. Against such a policy the verdict is never PASS:
at best INCOMPLETE, with the reason on the `policy.not_pending` line.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from avlib import canonjson, checks, dcap, fetch, gpu  # noqa: E402

ATTESTATION_PATH = "/attestation"
KEY_ATTESTATION_PATH = "/.well-known/adverserial-key-attestation"
HPKE_KEYS_PATH = "/.well-known/hpke-keys"
METER_JWKS_PATH = "/.well-known/adverserial-meter-jwks.json"
STATUSZ_PATH = "/statusz"
EXIT = {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}


def new_nonce() -> str:
    return canonjson.b64url(secrets.token_bytes(32))


def parse_time(s: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("endpoint", nargs="?", help="https:// base URL of the deployment")
    p.add_argument("--file", help="verify a saved attestation response instead of a live endpoint")
    p.add_argument("--deployment", help="directory holding policy.json, app-compose.json and docker-compose.yml")
    p.add_argument("--policy", help="policy file or https:// URL (overrides --deployment)")
    p.add_argument("--app-compose", help="published app-compose.json")
    p.add_argument("--docker-compose", help="published docker-compose.yml")
    p.add_argument("--nonce", help="nonce to send (live) or to require (file); default: 32 random bytes")
    p.add_argument("--at", help="verification time, RFC 3339 (default: now). Use the recorded time for old evidence")
    p.add_argument("--offline", action="store_true", help="never touch the network except the endpoint itself")
    p.add_argument("--pccs-url", default=dcap.INTEL_PCS, help="where to fetch Intel collateral (default: Intel PCS)")
    p.add_argument("--collateral", help="Intel collateral JSON saved by an earlier run")
    p.add_argument("--nras-jwks", help="NVIDIA NRAS JWKS saved by an earlier run")
    p.add_argument("--key-attestation-file", help="saved response of " + KEY_ATTESTATION_PATH)
    p.add_argument("--key-attestation-collateral", help="Intel collateral for the key-attestation quote")
    p.add_argument("--meter-jwks-file", help="saved response of " + METER_JWKS_PATH)
    p.add_argument("--statusz-file", help="saved response of " + STATUSZ_PATH + " (informational)")
    p.add_argument("--save-dir", help="write raw evidence, collateral, JWKS and key attestation here")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    return p


def gather(args) -> tuple[checks.Inputs, dict]:
    """Collect every input. Returns (inputs, raw blobs to save)."""
    dep = Path(args.deployment) if args.deployment else None
    policy_src = args.policy or (str(dep / "policy.json") if dep else None)
    if policy_src:
        policy = fetch.read_json(policy_src)
    elif getattr(args, "allow_no_policy", False):
        policy = {}  # recorder before any release is published: every policy check is skipped
    else:
        raise SystemExit("error: a policy is required (--policy or --deployment)")
    app_src = args.app_compose or (str(dep / "app-compose.json") if dep and (dep / "app-compose.json").exists() else None)
    dc_src = args.docker_compose or (str(dep / "docker-compose.yml") if dep and (dep / "docker-compose.yml").exists() else None)
    inp = checks.Inputs(response={}, policy=policy)
    inp.at = parse_time(args.at) if args.at else dt.datetime.now(dt.timezone.utc)
    inp.app_compose_raw = fetch.read_source(app_src) if app_src else None
    inp.docker_compose_text = fetch.read_source(dc_src).decode("utf-8") if dc_src else None
    raw: dict = {}

    if args.file:
        if args.endpoint:
            raise SystemExit("error: give an endpoint or --file, not both")
        raw["evidence"] = Path(args.file).read_bytes()
        inp.mode, inp.expected_nonce = "file", args.nonce
        for key, path in (("key-attestation", args.key_attestation_file), ("meter-jwks", args.meter_jwks_file),
                          ("statusz", args.statusz_file)):
            if path:
                raw[key] = Path(path).read_bytes()
    elif args.endpoint:
        ep = fetch.Endpoint(args.endpoint)
        nonce = args.nonce or new_nonce()
        status, body, spki = ep.get(ATTESTATION_PATH + "?nonce=" + nonce)
        if status != 200:
            raise fetch.FetchError("%s returned HTTP %d" % (ATTESTATION_PATH, status))
        raw["evidence"] = body
        inp.mode, inp.expected_nonce, inp.live_spki = "live", nonce, spki
        for path, key in ((KEY_ATTESTATION_PATH, "key-attestation"), (HPKE_KEYS_PATH, "hpke-keys"),
                          (METER_JWKS_PATH, "meter-jwks"), (STATUSZ_PATH, "statusz")):
            try:
                st, b, _ = ep.get(path)
                # The proxy sheds concurrent key-attestation requests with 503 while one quote is generated.
                for _ in range(3):
                    if not (key == "key-attestation" and st == 503):
                        break
                    time.sleep(2)
                    st, b, _ = ep.get(path)
                if st == 200:
                    raw[key] = b
                elif key == "key-attestation":
                    inp.key_attestation_error = "%s returned HTTP %d" % (path, st)
            except fetch.FetchError as exc:
                if key == "key-attestation":
                    inp.key_attestation_error = str(exc)
        inp.spki_seen = list(ep.spki_seen)
        inp.hpke_keys_body = raw.get("hpke-keys")
    else:
        raise SystemExit("error: give an endpoint URL or --file")

    inp.response = json.loads(raw["evidence"])
    if "key-attestation" in raw:
        try:
            inp.key_attestation = json.loads(raw["key-attestation"])
        except ValueError:
            inp.key_attestation_error = "key attestation response is not JSON"
    for key, field in (("meter-jwks", "meter_jwks"), ("statusz", "statusz")):
        try:
            setattr(inp, field, json.loads(raw[key]) if key in raw else None)
        except ValueError:
            setattr(inp, field, {"error": "response is not JSON"})  # fails the comparison, never silently skipped
    evidence = inp.response.get("evidence") if isinstance(inp.response, dict) else None
    quote_hex = evidence.get("tdx_quote") if isinstance(evidence, dict) else None

    # Intel collateral: file, else live fetch unless --offline.
    def collateral_for(path, hex_quote, label):
        if path:
            return Path(path).read_text()
        if args.offline or not hex_quote:
            return None
        try:
            return dcap.fetch_collateral(bytes.fromhex(hex_quote), args.pccs_url)
        except Exception as exc:  # network, library, malformed quote
            print("warning: could not fetch Intel collateral for %s: %s" % (label, exc), file=sys.stderr)
            return None

    inp.collateral_json = collateral_for(args.collateral, quote_hex, "the attestation quote")
    if inp.collateral_json:
        raw["collateral"] = inp.collateral_json.encode()
    if isinstance(inp.key_attestation, dict):
        kq = inp.key_attestation.get("quote")
        kq = kq if isinstance(kq, str) else None
        inp.key_attestation_collateral_json = collateral_for(args.key_attestation_collateral, kq, "the key-attestation quote")
        if inp.key_attestation_collateral_json and inp.key_attestation_collateral_json != inp.collateral_json:
            raw["key-attestation-collateral"] = inp.key_attestation_collateral_json.encode()

    # NVIDIA signing keys: file, else live fetch from the pinned origin unless --offline.
    if args.nras_jwks:
        raw["nras-jwks"] = Path(args.nras_jwks).read_bytes()
    elif not args.offline:
        try:
            raw["nras-jwks"] = fetch.read_source(gpu.NRAS_JWKS_URL)
        except fetch.FetchError as exc:
            print("warning: %s" % exc, file=sys.stderr)
    if "nras-jwks" in raw:
        inp.nras_jwks = json.loads(raw["nras-jwks"])
    return inp, raw


SUFFIX = {"evidence": "evidence.json", "collateral": "collateral.json", "nras-jwks": "nras-jwks.json",
          "key-attestation": "key-attestation.json", "key-attestation-collateral": "key-attestation-collateral.json",
          "hpke-keys": "hpke-keys.bin", "meter-jwks": "meter-jwks.json", "statusz": "statusz.json"}


def save(raw: dict, directory: str) -> dict:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for key, blob in raw.items():
        (out / SUFFIX[key]).write_bytes(blob)
        written[key] = str(out / SUFFIX[key])
    return written


def render(result: checks.Result) -> str:
    lines = []
    width = max(len(c["id"]) for c in result.checks)
    for c in result.checks:
        lines.append("[%-4s] %-*s  %s" % (c["status"], width, c["id"], c["title"]))
        if c["detail"]:
            lines.append("        %s  %s" % (" " * width, c["detail"]))
    counts = {s: sum(1 for c in result.checks if c["status"] == s) for s in ("PASS", "FAIL", "SKIP", "N/A", "WARN")}
    lines.append("")
    warnings = [c for c in result.checks if c["status"] == "WARN"]
    for c in warnings:
        # Said twice on purpose: once in the list, once next to the verdict, where it cannot be scrolled past.
        lines.append("WARNING (%s): %s" % (c["id"], c["detail"]))
    lines += [""] if warnings else []
    lines.append("%d passed, %d failed, %d skipped, %d not applicable, %d warning%s in %s mode" % (
        counts["PASS"], counts["FAIL"], counts["SKIP"], counts["N/A"], counts["WARN"], "" if counts["WARN"] == 1 else "s", result.mode))
    note = {"PASS": "every check that could run passed",
            "FAIL": "at least one property is false - do not trust this endpoint",
            "INCOMPLETE": "nothing failed, but skipped checks leave properties unproven"}[result.verdict]
    if result.verdict == "PASS" and result.mode == "file":
        note += "; a saved file proves nothing about freshness or the live TLS key"
    if result.verdict == "INCOMPLETE" and result.summary.get("policy_pending"):
        note = "the policy for this release is pending: " + result.summary["policy_pending"]
    if warnings:
        note += "; %d WARNING%s above: %s" % (len(warnings), "" if len(warnings) == 1 else "S", ", ".join(c["id"] for c in warnings))
    lines.append("VERDICT: %s (%s)" % (result.verdict, note))
    return "\n".join(lines)


def pending_hint(args) -> str | None:
    """The pending note of the local policy, for the message printed when the endpoint cannot be fetched."""
    src = args.policy or (str(Path(args.deployment) / "policy.json") if args.deployment else None)
    try:
        return checks.pending_note(json.loads(Path(src).read_text())) if src and "://" not in src else None
    except (OSError, ValueError):
        return None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        inp, raw = gather(args)
    except (fetch.FetchError, OSError, ValueError) as exc:
        hint = pending_hint(args)
        if args.json:
            print(json.dumps({"verdict": "ERROR", "error": str(exc), **({"policy_pending": hint} if hint else {})}))
        else:
            print("error: %s" % exc, file=sys.stderr)
            if hint:
                print("note: the policy for this release is pending: %s" % hint, file=sys.stderr)
        return 3
    result = checks.run(inp)
    out = result.to_json()
    if args.save_dir:
        out["saved"] = save(raw, args.save_dir)
    print(json.dumps(out, indent=2, sort_keys=True) if args.json else render(result))
    return EXIT[result.verdict]


if __name__ == "__main__":
    sys.exit(main())
