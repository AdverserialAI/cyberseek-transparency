#!/usr/bin/env python3
"""Fetch a fresh attestation, verify it, and append one line to the history.

    python history/record.py                       # live: https://api.adverserial.ai
    python history/record.py --file evidence.json --at 2026-01-01T00:00:00Z ...   # offline replay (tests)

One line is appended to history/attestations.jsonl on every run, whatever the
outcome, including "the endpoint was unreachable". Raw inputs are stored under
history/evidence/YYYY/MM/DD/<time>-<tag>/ so anybody can re-run the
verifier on them later:

    evidence.json          the attestation response, byte for byte
    collateral.json        the Intel collateral used for the TCB decision
    nras-jwks.json         the NVIDIA keys that signed the GPU tokens (only those)
    key-attestation.json   response of /.well-known/adverserial-key-attestation
    meter-jwks.json        response of /.well-known/adverserial-meter-jwks.json
    statusz.json           response of /statusz (unauthenticated, informational)
    verifier.json          this verifier's full per-check output

Exit status (the workflow reports anything but 0 in one issue, see tools/recorder_issue.py):
    0  verified, and the measurements match a release under deployments/
    1  verification FAILED
    2  verification INCOMPLETE (a check could not run)
    4  measurements match no release under deployments/
    5  endpoint unreachable or response unusable
    6  the endpoint answered and nothing failed, but the policy of the current
       release is still pending (deployments/README.md): the app id, compose
       hash and OS image match it, the verdict is INCOMPLETE, and it becomes
       PASS by itself once the policy is completed

Every line also carries "policy_state": "final", "pending", or null when
deployments/CURRENT names no usable release.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verify"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "history"))

import chainlib  # noqa: E402
import check_no_secrets  # noqa: E402
import validate_deployments  # noqa: E402
import verify as verifier  # noqa: E402
from avlib import canonjson, checks, fetch  # noqa: E402

DEFAULT_ENDPOINT = "https://api.adverserial.ai"
MEASURED = ("mrtd", "rtmr0", "rtmr1", "rtmr2")
IDENTITY = ("app_id", "compose_hash", "os_image_hash")
EXIT_UNMATCHED, EXIT_UNREACHABLE, EXIT_PENDING = 4, 5, 6


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def used_nras_keys(evidence_raw: bytes, jwks_raw: bytes) -> bytes:
    """Keep only the NVIDIA keys that signed tokens in this evidence (the full set is ~0.5 MB)."""
    try:
        tokens = json.loads(evidence_raw)["evidence"]["gpu_evidence"]["eat_jwts"]
        kids = {json.loads(canonjson.b64url_decode(t.split(".")[0])).get("kid") for t in tokens}
        keys = [k for k in json.loads(jwks_raw).get("keys", []) if k.get("kid") in kids]
    except (KeyError, TypeError, ValueError, AttributeError):
        keys = []
    return json.dumps({"keys": keys}, sort_keys=True, separators=(",", ":")).encode()


def current_deployment(deployments: Path) -> Path | None:
    name, _ = validate_deployments.read_current(deployments)
    d = deployments / name
    if name and d.is_dir() and not validate_deployments.is_placeholder(d) and (d / "policy.json").exists():
        return d
    return None


def match_deployment(summary: dict, deployments: Path) -> str | None:
    observed = dict(summary.get("measurements") or {})
    observed.update({k: summary.get(k) for k in IDENTITY})
    for name, pins in validate_deployments.load_measurements(deployments).items():
        if all(pins.get(k) and pins.get(k) == observed.get(k) for k in MEASURED + IDENTITY):
            return name
    return None


def previous_measurements(history_file: Path) -> dict | None:
    for line in reversed(chainlib.read_lines(history_file)):
        entry = json.loads(line)
        if entry.get("measurements"):
            return {"measurements": entry["measurements"], **{k: entry.get(k) for k in IDENTITY}}
    return None


def record(args) -> tuple[dict, int]:
    root = Path(args.root)
    history_file = root / "history" / "attestations.jsonl"
    deployments = root / "deployments"
    chainlib.validate(history_file)  # never extend a broken chain
    now = verifier.parse_time(args.at) if args.at else dt.datetime.now(dt.timezone.utc)
    now = now.replace(microsecond=0)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = verifier.new_nonce()
    dep = current_deployment(deployments)
    pending = validate_deployments.load_pending(deployments).get(dep.name) if dep else None

    argv = ["--at", stamp]
    argv += ["--file", args.file] if args.file else [args.endpoint, "--nonce", nonce]
    argv += ["--deployment", str(dep)] if dep else []
    for flag in ("collateral", "nras_jwks", "key_attestation_file", "meter_jwks_file", "statusz_file", "pccs_url"):
        if getattr(args, flag):
            argv += ["--" + flag.replace("_", "-"), getattr(args, flag)]
    if args.offline:
        argv.append("--offline")
    vargs = verifier.build_parser().parse_args(argv)
    vargs.allow_no_policy = True

    entry = {"v": 1, "timestamp": stamp, "endpoint": args.file and "file" or args.endpoint,
             "expected_deployment": dep.name if dep else None,
             "policy_state": None if not dep else "pending" if pending is not None else "final"}
    try:
        inp, raw = verifier.gather(vargs)
    except (fetch.FetchError, OSError, ValueError) as exc:
        entry.update({"nonce": None if args.file else nonce, "verdict": "UNREACHABLE", "error": " ".join(str(exc).split())[:300]})
        return entry, EXIT_UNREACHABLE

    if "nras-jwks" in raw:
        raw["nras-jwks"] = used_nras_keys(raw["evidence"], raw["nras-jwks"])
        inp.nras_jwks = json.loads(raw["nras-jwks"])
    result = checks.run(inp)
    summary = result.summary
    matched = match_deployment(summary, deployments)
    before = previous_measurements(history_file)
    observed = {"measurements": summary.get("measurements"), **{k: summary.get(k) for k in IDENTITY}}
    verifier_out = json.dumps(result.to_json(), indent=2, sort_keys=True).encode() + b"\n"

    # Store raw inputs. Evidence is public by construction, but scan it anyway.
    # The directory name uses only characters we control: the endpoint's echo of
    # the nonce is untrusted input and must never shape a path.
    tag = hashlib.sha256((nonce if not args.file else sha256(raw["evidence"])).encode()).hexdigest()[:8]
    rel_dir = Path("history") / "evidence" / now.strftime("%Y/%m/%d") / ("%s-%s" % (now.strftime("%H%M%SZ"), tag))
    out_dir = root / rel_dir
    out_dir.mkdir(parents=True, exist_ok=False)
    files = {}
    for key, blob in list(raw.items()) + [("verifier", verifier_out)]:
        name = verifier.SUFFIX.get(key, key + ".json")
        (out_dir / name).write_bytes(blob)
        hits = check_no_secrets.scan_file(out_dir / name, "evidence")
        if hits:
            (out_dir / name).unlink()
            entry.setdefault("withheld", []).append(name)
            continue
        files[key] = {"path": str(rel_dir / name), "sha256": sha256(blob)}

    keys = summary.get("keys") or {}
    entry.update({
        "nonce": summary.get("nonce"),
        "nonce_is_ours": inp.expected_nonce is not None and summary.get("nonce") == inp.expected_nonce,
        "issued_at": summary.get("issued_at"),
        "verdict": result.verdict,
        "mode": result.mode,
        "failed": [c["id"] for c in result.checks if c["status"] == checks.FAIL],
        "skipped": [c["id"] for c in result.checks if c["status"] == checks.SKIP],
        "measurements": summary.get("measurements"),
        "app_id": summary.get("app_id"),
        "compose_hash": summary.get("compose_hash"),
        "os_image_hash": summary.get("os_image_hash"),
        "instance_id": summary.get("instance_id"),
        "compose_digest": summary.get("compose_digest"),
        "proxy_version": summary.get("proxy_version"),
        "tcb_status": summary.get("tcb_status"),
        "gpu_count": (summary.get("gpu") or {}).get("gpu_count"),
        "tls_spki_sha256": summary.get("tls_spki_sha256"),
        "live_tls_spki_sha256": summary.get("live_tls_spki_sha256"),
        "key_fingerprints": {
            "receipt_kid": keys.get("receipt_kid"),
            "ehbp_public_key_sha256": keys.get("ehbp_public_key_sha256"),
            "meter_kid": keys.get("meter_kid"),
            "key_statement_sha256": summary.get("key_statement_sha256"),
        },
        "keys_origin": keys.get("keys_origin"),
        "deployment": matched,
        "measurements_changed": bool(before) and before != observed,
        "evidence_sha256": sha256(raw["evidence"]),
        "files": files,
    })
    if result.verdict == "FAIL":
        return entry, 1
    if not matched and pending is not None and all(pending.get(k) and pending[k] == summary.get(k) for k in IDENTITY):
        # Not a match (there are no measurements to match yet), and never exit 0.
        entry["pending_deployment"] = dep.name
        return entry, EXIT_PENDING
    if not matched:
        return entry, EXIT_UNMATCHED
    return entry, 2 if result.verdict == "INCOMPLETE" else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    ap.add_argument("--root", default=str(ROOT), help="repository root (holds history/ and deployments/)")
    ap.add_argument("--file", help="record a saved attestation response instead of fetching one")
    ap.add_argument("--at", help="timestamp to record and verify at (default: now)")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--collateral")
    ap.add_argument("--nras-jwks")
    ap.add_argument("--key-attestation-file")
    ap.add_argument("--meter-jwks-file")
    ap.add_argument("--statusz-file")
    ap.add_argument("--pccs-url")
    ap.add_argument("--github-output", help="append status=..., verdict=..., head=... lines to this file")
    args = ap.parse_args(argv)
    try:
        entry, code = record(args)
    except chainlib.ChainError as exc:
        print("error: history chain is broken, refusing to append: %s" % exc, file=sys.stderr)
        return 3
    entry, head = chainlib.append(Path(args.root) / "history" / "attestations.jsonl", entry)
    print(json.dumps({"exit": code, "head": head, "entry": entry}, indent=2, sort_keys=True))
    if args.github_output:
        with open(args.github_output, "a") as fh:
            fh.write("exit_code=%d\nverdict=%s\nhead=%s\nseq=%d\npolicy_state=%s\ndeployment=%s\nevidence_dir=%s\n" % (
                code, entry["verdict"], head, entry["seq"], entry.get("policy_state") or "", entry.get("deployment") or "",
                str(Path(entry["files"]["evidence"]["path"]).parent) if entry.get("files", {}).get("evidence") else ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
