#!/usr/bin/env python3
"""Validate everything under deployments/.

    python tools/validate_deployments.py [--fail-on-pending] [--immutable-since GIT_REV] [deployments]

For every release directory (any directory except TEMPLATE):

  * policy.json, app-compose.json, docker-compose.yml exist;
  * no file looks like it contains a credential (tools/check_no_secrets.py);
  * policy.json carries well-formed TDX pins;
  * SHA-256(app-compose.json) == policy.tdx.compose_hash;
  * docker-compose.yml is byte-identical to docker_compose_file in app-compose.json;
  * COMPOSE_DIGEST recomputes and equals policy.deployment_configuration_digest;
  * every image is pinned by digest;
  * the verifier's static compose checks pass: the operator-supplied variables
    equal policy.verifier.allowed_envs, the proxy is configured to generate
    its keys inside the VM, the model server is isolated on an internal
    network, and only the proxy publishes a port;
  * CHANGELOG.md has a section for the release.

deployments/CURRENT must name an existing release on its first line; further
lines are comments and must start with "#". While that release is pending,
CURRENT must carry the "# Status: ROLLED OUT, NOT YET VERIFIED LIVE" comment,
and must not carry it once the policy is final. A directory that contains a
file named PLACEHOLDER is skipped with a warning, and is an error unless
--allow-placeholders is given.

Pending releases
----------------
A release can be published before its first live attestation exists (rolled
out, service not answering yet). Its policy.json then says so explicitly:

    "status": "pending",
    "pending": {"reason": "...", "missing": ["tdx.mrtd", "tdx.rtmr0", ...]}

and simply omits the values that only a live attestation can supply. Nothing
else is relaxed: the secret scan, the compose-hash check, the COMPOSE_DIGEST
check and every static compose check apply in full, tdx.app_id,
tdx.compose_hash and tdx.os_image_hash are still required, and "missing" must
name exactly what is absent. Such a release is reported as PENDING (exit 0, or
1 with --fail-on-pending); verify/verify.py never returns PASS against it.

--immutable-since GIT_REV fails if a published release file changed since that
revision. The one permitted change is completing a pending policy.json: values
may be added, none that was published may change or disappear.

Prints one JSON line per release with --json (used by the workflows).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verify"))
sys.path.insert(0, str(ROOT / "tools"))

import check_no_secrets  # noqa: E402
from avlib import compose  # noqa: E402

REQUIRED = ("policy.json", "app-compose.json", "docker-compose.yml")
HEX_LEN = {"mrtd": 96, "rtmr0": 96, "rtmr1": 96, "rtmr2": 96, "app_id": 40, "compose_hash": 64, "os_image_hash": 64}
MEASUREMENT_KEYS = tuple(HEX_LEN)
PENDING = "pending"
# What a pending policy may leave out: only values that the first live
# attestation supplies. The identity of the release (app_id, compose_hash,
# os_image_hash) is known at rollout and is never optional.
PENDING_MEASUREMENTS = ("mrtd", "rtmr0", "rtmr1", "rtmr2")
PENDING_PINS = ("tls_spki_sha256", "receipt_keys", "model_artifact_digest")
TOP_LEVEL_FILES = ("CURRENT", "CHANGELOG.md", "README.md")
NOT_VERIFIED = "ROLLED OUT, NOT YET VERIFIED LIVE"
CURRENT_STATUS = "# Status: " + NOT_VERIFIED


def releases(root: Path) -> list[Path]:
    return sorted(d for d in root.iterdir() if d.is_dir() and d.name != "TEMPLATE" and not d.name.startswith("."))


def is_placeholder(directory: Path) -> bool:
    return (directory / "PLACEHOLDER").exists()


def read_current(root: Path) -> tuple[str, list[str]]:
    """(release name, comment lines) of deployments/CURRENT. The name is the first line; `head -n 1` reads it."""
    try:
        lines = (root / "CURRENT").read_text().splitlines()
    except OSError:
        return "", []
    return (lines[0].strip() if lines else ""), [line for line in lines[1:] if line.strip()]


def current_text(tag: str, policy: dict | None = None) -> str:
    """What deployments/CURRENT must contain for this release: the name, and for a pending one, why."""
    if not is_pending(policy):
        return tag + "\n"
    info = policy.get(PENDING) if isinstance(policy.get(PENDING), dict) else {}
    words, lines, line = str(info.get("detail") or "").split(), [], "#"
    for word in words:
        if len(line) + 1 + len(word) > 78:
            lines.append(line)
            line = "#"
        line += " " + word
    lines += [line] if words else []
    return "\n".join([tag, CURRENT_STATUS, "# The policy of this release is pending: %s." % pending_reason(policy), *lines]) + "\n"


def is_pending(policy) -> bool:
    """A policy that carries either pending marker is pending; a half-removed marker never counts as final."""
    return isinstance(policy, dict) and (policy.get("status") == PENDING or PENDING in policy)


def pending_reason(policy: dict) -> str:
    info = policy.get(PENDING) if isinstance(policy.get(PENDING), dict) else {}
    return str(info.get("reason") or "pending first live attestation")


def pending_errors(policy: dict) -> list[str]:
    """The pending marker must be well formed and must name exactly what is absent."""
    info = policy.get(PENDING)
    if policy.get("status") != PENDING or not isinstance(info, dict):
        return ['a pending policy needs both "status": "pending" and a "pending" object; remove both to make it final']
    errors = []
    if not isinstance(info.get("reason"), str) or not info["reason"].strip():
        errors.append("policy.pending.reason must say why the release is pending")
    missing = info.get("missing")
    allowed = ["tdx." + k for k in PENDING_MEASUREMENTS] + list(PENDING_PINS)
    if not isinstance(missing, list) or not missing or any(m not in allowed for m in missing) or len(set(missing)) != len(missing):
        return errors + ["policy.pending.missing must be a non-empty list drawn from: %s" % ", ".join(allowed)]
    tdx = policy.get("tdx") if isinstance(policy.get("tdx"), dict) else {}
    for name in missing:
        holder, key = (tdx, name[4:]) if name.startswith("tdx.") else (policy, name)
        if key in holder:
            errors.append("policy.pending.missing lists %s, but the policy has a value for it" % name)
    for key in PENDING_MEASUREMENTS:
        if key not in tdx and "tdx." + key not in missing:
            errors.append("policy.tdx.%s is absent but not listed in policy.pending.missing" % key)
    return errors


def load_pending(root: Path) -> dict:
    """{release name: {app_id, compose_hash, os_image_hash}} for releases whose policy is pending."""
    out = {}
    for d in releases(root):
        if is_placeholder(d) or not (d / "policy.json").exists():
            continue
        try:
            policy = json.loads((d / "policy.json").read_text())
        except ValueError:
            continue
        if is_pending(policy):
            tdx = policy.get("tdx") if isinstance(policy.get("tdx"), dict) else {}
            out[d.name] = {k: tdx.get(k) for k in MEASUREMENT_KEYS if k not in PENDING_MEASUREMENTS}
    return out


def load_measurements(root: Path) -> dict:
    """{release name: {mrtd, rtmr0-2, app_id, compose_hash, os_image_hash}} for real releases.

    A pending release is not in this map: it has no measurements to match."""
    out = {}
    for d in releases(root):
        if is_placeholder(d) or not (d / "policy.json").exists():
            continue
        try:
            policy = json.loads((d / "policy.json").read_text())
        except ValueError:
            continue
        if is_pending(policy):
            continue
        tdx = policy.get("tdx", {})
        out[d.name] = {k: tdx.get(k) for k in MEASUREMENT_KEYS}
    return out


def check_release(policy_raw: bytes, app_raw: bytes, compose_text: str, label: str = "") -> list[str]:
    """Every rule a release must satisfy, on the three documents held in memory."""
    errors = []
    for name, data, is_json in (("policy.json", policy_raw.decode("utf-8", "replace"), True),
                                ("app-compose.json", app_raw.decode("utf-8", "replace"), True),
                                ("docker-compose.yml", compose_text, False)):
        errors += check_no_secrets.scan_document(label + name, data, is_json)
    try:
        policy = json.loads(policy_raw)
    except ValueError:
        return errors + ["policy.json is not valid JSON"]
    if not isinstance(policy, dict) or "PLACEHOLDER" in policy or policy.get("status") == "placeholder":
        return errors + ["policy.json is a placeholder, not a policy"]
    tdx = policy.get("tdx", {})
    absent_ok = ()
    if is_pending(policy):
        errors += pending_errors(policy)
        absent_ok = tuple(k for k in PENDING_MEASUREMENTS if k not in tdx)   # a present value must still be well formed
    for key, length in HEX_LEN.items():
        if key in absent_ok:
            continue
        if not re.fullmatch(r"[0-9a-f]{%d}" % length, str(tdx.get(key, ""))):
            errors.append("policy.tdx.%s must be %d lowercase hex characters" % (key, length))
    published, canonical = compose.app_compose_hash(app_raw)
    if published != tdx.get("compose_hash"):
        hint = " (the file is not in canonical form; run tools/canonicalize_app_compose.py)" if canonical == tdx.get("compose_hash") else ""
        errors.append("SHA-256(app-compose.json) is %s, policy.tdx.compose_hash is %s%s" % (published, tdx.get("compose_hash"), hint))
    app = {}
    try:
        app = json.loads(app_raw)
        if app.get("docker_compose_file") != compose_text:
            errors.append("docker-compose.yml differs from docker_compose_file inside app-compose.json")
    except ValueError:
        errors.append("app-compose.json is not valid JSON")
    try:
        declared, computed = compose.self_digest(compose_text)
        if declared != computed:
            errors.append("COMPOSE_DIGEST is %s but recomputes to %s" % (declared, computed))
        want = policy.get("deployment_configuration_digest")
        if want and want != computed:
            errors.append("policy.deployment_configuration_digest is %s, compose recomputes to %s" % (want, computed))
    except ValueError as exc:
        errors.append(str(exc))
    return errors + compose_rules(policy, app, compose_text)


def compose_rules(policy: dict, app: dict, compose_text: str) -> list[str]:
    """The verifier's static compose checks (no attestation needed), so a release that would fail them is never published."""
    vcfg = policy.get("verifier") or {}
    proxy = vcfg.get("proxy_service") or compose.DEFAULT_PROXY_SERVICE
    inference = vcfg.get("inference_service") or compose.DEFAULT_INFERENCE_SERVICE
    try:
        doc = compose.load(compose_text)
    except compose.ComposeViolation as exc:
        return [str(exc)]
    if not isinstance(vcfg.get("allowed_envs"), list):
        return ["policy.verifier.allowed_envs must list the operator-supplied variable names"]

    def images():
        refs = compose.check_images(doc)
        for key in ("runtime_image_digest", "proxy_image_digest"):
            if policy.get(key) and not any(r.endswith("@" + policy[key]) for r in refs):
                raise compose.ComposeViolation("policy.%s %s is not an image in the compose" % (key, policy[key]))

    errors = []
    for rule in (images,
                 lambda: compose.check_sealed_envs(doc, app.get("allowed_envs"), vcfg["allowed_envs"]),
                 lambda: compose.check_keys_in_enclave(doc, compose_text, app.get("allowed_envs"), proxy, vcfg.get("operator_key_envs"),
                                                       vcfg.get("enclave_key_proxy_digests"), policy.get("proxy_image_digest")),
                 lambda: compose.check_inference_isolated(doc, inference, proxy),
                 lambda: compose.check_single_ingress(doc, proxy)):
        try:
            rule()
        except compose.ComposeViolation as exc:
            errors.append(str(exc))
    return errors


def validate_release(d: Path, changelog: str) -> list[str]:
    missing = [f for f in REQUIRED if not (d / f).is_file()]
    if missing:
        return ["missing files: %s" % ", ".join(missing)]
    errors = []
    for f in sorted(p for p in d.rglob("*") if p.is_file() and p.name not in REQUIRED):
        errors += check_no_secrets.scan_file(f)
    errors += check_release((d / "policy.json").read_bytes(), (d / "app-compose.json").read_bytes(),
                            (d / "docker-compose.yml").read_bytes().decode("utf-8"), str(d) + "/")
    if not re.search(r"^##\s+%s\s*$" % re.escape(d.name), changelog, re.M):
        errors.append("deployments/CHANGELOG.md has no '## %s' section" % d.name)
    return errors


def completion_errors(old, new, path="policy") -> list[str]:
    """What completing a pending policy may not do: change or drop anything that was published.

    Keys may be added anywhere (the measurements, the pins). The pending
    marker itself may change or go."""
    errors = []
    for key, value in old.items():
        if path == "policy" and key in ("status", PENDING):
            continue
        where = "%s.%s" % (path, key)
        if not isinstance(new, dict) or key not in new:
            errors.append("%s was published and is now missing" % where)
        elif isinstance(value, dict) and isinstance(new[key], dict):
            errors += completion_errors(value, new[key], where)
        elif value != new[key]:
            errors.append("%s was published as %s and is now %s" % (where, json.dumps(value), json.dumps(new[key])))
    return errors


def _git(root: Path, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True)


def immutability_errors(root: Path, rev: str) -> list[str]:
    """Files of a published release must not change after `rev`, except a pending policy.json being completed."""
    base = _git(root, "merge-base", rev, "HEAD")
    if base.returncode != 0:
        return ["cannot compare with %s: %s" % (rev, base.stderr.decode(errors="replace").strip())]
    base = base.stdout.decode().strip()
    diff = _git(root, "diff", "--name-status", "--no-renames", "-z", "--relative", base, "--", ".")
    if diff.returncode != 0:
        return ["git diff failed: %s" % diff.stderr.decode(errors="replace").strip()]
    fields = diff.stdout.decode().split("\0")
    errors = []
    for status, name in zip(fields[0::2], fields[1::2]):
        parts = Path(name).parts
        if status == "A" or (len(parts) == 1 and name in TOP_LEVEL_FILES):
            continue
        if status == "M" and len(parts) == 2 and parts[1] == "policy.json":
            old = _git(root, "show", "%s:./%s" % (base, name))
            try:
                before, after = json.loads(old.stdout), json.loads((root / name).read_text())
            except (OSError, ValueError):
                before = after = None
            if old.returncode == 0 and is_pending(before) and isinstance(after, dict):
                errors += ["%s: %s" % (name, e) for e in completion_errors(before, after)]
                continue
        errors.append("%s: a file of a published release was %s" % (name, "deleted" if status == "D" else "modified"))
    return errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Validate everything under deployments/.")
    ap.add_argument("root", nargs="?", default=str(ROOT / "deployments"))
    ap.add_argument("--allow-placeholders", action="store_true")
    ap.add_argument("--fail-on-pending", action="store_true", help="exit 1 while any release still has a pending policy")
    ap.add_argument("--immutable-since", metavar="GIT_REV",
                    help="fail if a published release file changed since this revision (completing a pending policy.json is allowed)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root)
    changelog = (root / "CHANGELOG.md").read_text() if (root / "CHANGELOG.md").exists() else ""
    failed, report = False, []
    for d in releases(root):
        if is_placeholder(d):
            status, errors = "placeholder", []
            failed |= not args.allow_placeholders
        else:
            errors = validate_release(d, changelog)
            status = "invalid" if errors else "valid"
            failed |= bool(errors)
            try:
                policy = json.loads((d / "policy.json").read_text())
            except (OSError, ValueError):
                policy = None
            if is_pending(policy):
                note = pending_reason(policy)
                status = "invalid" if errors else PENDING
                failed |= args.fail_on_pending
        report.append({"release": d.name, "status": status, "errors": errors, **({"pending": note} if status == PENDING else {})})
    current, comments = read_current(root)
    top = []
    if not current or "/" in current or current.startswith(".") or not (root / current).is_dir():
        top.append("deployments/CURRENT must name an existing release directory on its first line (found %r)" % current)
    else:
        if any(not c.startswith("#") for c in comments):
            top.append("deployments/CURRENT: every line after the first must be a comment starting with '#'")
        state = next((r["status"] for r in report if r["release"] == current), None)
        says_unverified = any(c.startswith(CURRENT_STATUS) for c in comments)
        if state == PENDING and not says_unverified:
            top.append("deployments/CURRENT names a pending release and must say so: add the line %r" % CURRENT_STATUS)
        if state == "valid" and says_unverified:
            top.append("deployments/CURRENT still says %r, but the policy of %s is final" % (NOT_VERIFIED, current))
    failed |= bool(top)
    if args.immutable_since:
        changed = immutability_errors(root, args.immutable_since)
        top += changed
        failed |= bool(changed)
    if args.json:
        print(json.dumps({"current": current, "releases": report, "errors": top}, indent=2))
    else:
        for r in report:
            print("[%s] %s%s" % (r["status"].upper(), r["release"], ": " + r["pending"] if r.get("pending") else ""))
            for e in r["errors"]:
                print("    - %s" % e)
        for e in top:
            print("error: %s" % e)
        print("FAIL" if failed else "OK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
