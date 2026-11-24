#!/usr/bin/env python3
"""Turn a deployed VM's description into a publishable release directory.

    phala cvms get <id> --json > /somewhere/outside/this/repo/cvm.json
    python tools/prepare_release.py /somewhere/cvm.json policy.json v0.1.0-rc.33

Reads the Phala Cloud description of the running VM (it holds the dstack
manifest in "compose_file" and its measured hash in "compose_hash"), a policy
written for that deployment, and a release tag. Writes

    deployments/<tag>/docker-compose.yml   the compose text, byte for byte
    deployments/<tag>/app-compose.json     the manifest in the exact bytes the guest measured
    deployments/<tag>/policy.json          the policy, byte for byte

then points deployments/CURRENT at <tag> (first line; for a pending release the
following comment lines say that it is not verified live yet, and why) and adds a `## <tag>` section to
deployments/CHANGELOG.md.

It REFUSES, and writes nothing at all, when

  * the manifest bytes rebuilt from the VM description (the rule is in
    verify/avlib/compose.py) do not hash to the VM's compose_hash, or the
    compose text does not hash to its docker_compose_hash;
  * the policy disagrees with the VM: tdx.compose_hash, tdx.app_id,
    tdx.os_image_hash, deployment_configuration_digest (the COMPOSE_DIGEST),
    or tdx.gpu_policy_hash is not the hash of the manifest's
    requirements.gpu_policy (manifest version 3);
  * anything in the three files looks like a credential
    (tools/check_no_secrets.py rules);
  * a static verifier check would fail on the release (operator-supplied
    variables, keys generated in the VM, model-server isolation, single
    published port, images pinned): see tools/validate_deployments.py;
  * deployments/<tag> already exists. Published releases are immutable
    (the one exception is --complete, below).

Pending releases. A release that is rolled out but has not answered an
attestation yet can still be published, honestly: write the policy with
"status": "pending" and a "pending" object naming what is missing (see
tools/validate_deployments.py), leave those values out, and pass --pending.
Every check above still applies; only the measurements that a live attestation
supplies may be absent. The verifier returns INCOMPLETE, never PASS, against a
pending policy.

    python tools/prepare_release.py cvm.json pending-policy.json <tag> --pending

Once the endpoint answers, complete it. --complete replaces only policy.json
of an existing pending release, and only if the new policy is final, keeps
every value that was published, and the VM description still reproduces the
published manifest and compose byte for byte:

    python tools/prepare_release.py cvm.json final-policy.json <tag> --complete --completed-on "<UTC time>"

A compose that contains literal secrets cannot be published: its hash covers
them, so they cannot be redacted. Redeploy with `${NAME}` references first.

The VM description itself is only an input. Keep it out of the repository.
Exit status: 0 written, 1 refused, 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verify"))
sys.path.insert(0, str(ROOT / "tools"))

import validate_deployments  # noqa: E402
from avlib import compose  # noqa: E402

TAG = re.compile(r"^v[0-9][0-9A-Za-z.+-]{0,62}$")
MARKER = "<!-- Add new releases directly below this line. -->"
TODO = "TO BE FILLED IN"


class Refused(Exception):
    def __init__(self, reasons):
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


def build(snapshot: dict, policy_raw: bytes, expect_compose_hash: str | None = None) -> dict:
    """Check everything. Returns the three file contents and facts for the changelog, or raises Refused."""
    app = snapshot.get("compose_file") if isinstance(snapshot, dict) else None
    if not isinstance(app, dict) or not isinstance(app.get("docker_compose_file"), str):
        raise Refused(['the VM description has no "compose_file" object with a docker_compose_file'])
    expected = expect_compose_hash or snapshot.get("compose_hash")
    if not expected:
        raise Refused(['the VM description has no "compose_hash" (pass --compose-hash with the measured value)'])
    app_raw = compose.canonical_app_compose(app)
    text = app["docker_compose_file"]
    actual = compose.sha256_hex(app_raw)
    reasons = []
    if actual != expected:
        reasons.append("hash mismatch: the canonical app-compose hashes to %s, the VM reports compose_hash %s" % (actual, expected))
    if snapshot.get("docker_compose_hash") and compose.sha256_hex(text.encode("utf-8")) != snapshot["docker_compose_hash"]:
        reasons.append("hash mismatch: the compose text does not hash to the VM's docker_compose_hash")
    try:
        policy = json.loads(policy_raw)
    except ValueError:
        raise Refused(reasons + ["the policy is not valid JSON"]) from None
    tdx = policy.get("tdx", {}) if isinstance(policy, dict) else {}
    for name, ours, theirs in (("compose_hash", tdx.get("compose_hash"), actual),
                               ("app_id", tdx.get("app_id"), snapshot.get("app_id")),
                               ("os_image_hash", tdx.get("os_image_hash"), (snapshot.get("os") or {}).get("os_image_hash"))):
        if theirs and ours != theirs:
            reasons.append("hash mismatch: policy.tdx.%s is %s, the VM has %s" % (name, ours, theirs))
    reasons += validate_deployments.check_release(policy_raw, app_raw, text)
    if reasons:
        raise Refused(list(dict.fromkeys(reasons)))
    declared, _ = compose.self_digest(text)
    gpu = compose.gpu_policy(app) if compose.measures_gpu_policy(app) else None
    return {"app-compose.json": app_raw, "docker-compose.yml": text.encode("utf-8"), "policy.json": policy_raw,
            "facts": {"compose_hash": actual, "compose_digest": declared, "os_image_hash": tdx.get("os_image_hash"),
                      "images": compose.images(text), "allowed_envs": sorted(app.get("allowed_envs") or []),
                      "proxy_version": policy.get("proxy_version"),
                      "gpu_policy": None if gpu is None else "%s, gpu_policy_hash %s" % (
                          json.dumps(gpu, sort_keys=True, separators=(",", ":")), compose.gpu_policy_hash(gpu)),
                      "gpu_os_attestation": None if gpu is None else gpu.get("attest_gpu", True) is not False,
                      "pending": validate_deployments.pending_reason(policy) if validate_deployments.is_pending(policy) else None}}


STATUS_PENDING = "- Status: " + validate_deployments.NOT_VERIFIED + ". The policy is pending: %s"
MEASUREMENTS_PENDING = "- MRTD, RTMR0-2: pending first live attestation"
MEASUREMENTS_FINAL = "- MRTD, RTMR0-2: see policy.json"
FIRST_ENTRY = "- First history entry under this release: %s"


def changelog_section(tag: str, facts: dict, rolled_out: str | None, changes: str | None, os_image: str | None = None) -> str:
    return "\n".join([
        "## %s" % tag,
        *([STATUS_PENDING % facts["pending"]] if facts.get("pending") else []),
        "- Rolled out: %s" % (rolled_out or TODO),
        "- Changes: %s" % (changes or TODO),
        "- Proxy: %s" % facts["proxy_version"],
        "- compose_hash: %s" % facts["compose_hash"],
        "- COMPOSE_DIGEST: %s" % facts["compose_digest"],
        "- OS image: %sos_image_hash %s" % (os_image + ", " if os_image else "", facts["os_image_hash"]),
        MEASUREMENTS_PENDING if facts.get("pending") else MEASUREMENTS_FINAL,
        *(["- GPU policy (requirements.gpu_policy in the measured manifest): %s. %s" % (
            facts["gpu_policy"], "The OS attests the GPUs before releasing keys" if facts.get("gpu_os_attestation")
            else "GPU attestation by the OS is DISABLED by this policy")] if facts.get("gpu_policy") else []),
        "- Images: %s" % ", ".join(facts["images"]),
        "- Operator-supplied variables (allowed_envs): %s" % (", ".join(facts["allowed_envs"]) or "none"),
        FIRST_ENTRY % ("none yet, pending first live attestation" if facts.get("pending") else TODO),
        "", ""])


def drop_section(changelog: str, name: str) -> str:
    return re.sub(r"(?ms)^## %s[ \t]*\n.*?(?=^## |\Z)" % re.escape(name), "", changelog)


def complete_release(deployments: Path, tag: str, built: dict, completed_on: str | None, dry_run: bool = False) -> list[str]:
    """Replace the pending policy.json of an existing release. Returns reasons to refuse; writes only when there are none."""
    target = deployments / tag
    try:
        old = json.loads((target / "policy.json").read_text())
    except (OSError, ValueError):
        return ["%s has no readable policy.json" % target]
    if not validate_deployments.is_pending(old):
        return ["%s is not pending; published releases are never rewritten" % target]
    if validate_deployments.is_superseded(validate_deployments.changelog_text(deployments), tag):
        return ["%s is marked superseded in CHANGELOG.md: it never served and is never completed" % target]
    reasons = []
    if built["facts"]["pending"]:
        reasons.append("the new policy is still marked pending; --complete needs the final policy")
    for name in ("app-compose.json", "docker-compose.yml"):
        if not (target / name).is_file() or (target / name).read_bytes() != built[name]:
            reasons.append("the VM description does not reproduce the published %s byte for byte" % name)
    reasons += validate_deployments.completion_errors(old, json.loads(built["policy.json"]))
    if reasons or dry_run:
        return reasons
    staging = target / ".policy.json.staging"
    staging.write_bytes(built["policy.json"])
    os.replace(staging, target / "policy.json")
    path = deployments / "CHANGELOG.md"
    changelog = path.read_text() if path.exists() else ""
    section = re.search(r"(?ms)^## %s[ \t]*\n.*?(?=^## |\Z)" % re.escape(tag), changelog)
    if section:
        text = section.group(0)
        text = re.sub(r"(?m)^- Status: .*$", lambda m: "- Status: policy completed %s from the first live attestation "
                      "(published as pending before that)" % (completed_on or TODO), text, count=1)
        text = text.replace(MEASUREMENTS_PENDING, MEASUREMENTS_FINAL)
        text = re.sub(r"(?m)^%s$" % re.escape(FIRST_ENTRY) .replace("%s", ".*pending.*"), lambda m: FIRST_ENTRY % TODO, text, count=1)
        path.write_text(changelog[:section.start()] + text + changelog[section.end():])
    if validate_deployments.read_current(deployments)[0] == tag:
        (deployments / "CURRENT").write_text(validate_deployments.current_text(tag))
    return []


def write_release(deployments: Path, tag: str, built: dict, rolled_out=None, changes=None, retire_placeholder=False, os_image=None) -> Path:
    target = deployments / tag
    staging = deployments / (".staging-" + tag)
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    try:
        for name in validate_deployments.REQUIRED:
            (staging / name).write_bytes(built[name])
        os.rename(staging, target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    path = deployments / "CHANGELOG.md"
    changelog = path.read_text() if path.exists() else "# Deployment changelog\n\n%s\n\n" % MARKER
    placeholder = deployments / "PENDING"
    if retire_placeholder and (placeholder / "PLACEHOLDER").exists():
        shutil.rmtree(placeholder)
        changelog = drop_section(changelog, "PENDING")
    section = changelog_section(tag, built["facts"], rolled_out, changes, os_image)
    if MARKER in changelog:
        head, tail = changelog.split(MARKER, 1)
        changelog = head + MARKER + "\n\n" + section + tail.lstrip("\n")
    else:
        changelog = changelog.rstrip("\n") + "\n\n" + section
    path.write_text(changelog.rstrip("\n") + "\n")
    (deployments / "CURRENT").write_text(validate_deployments.current_text(tag, json.loads(built["policy.json"])))
    return target


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cvm_json", help="output of `phala cvms get <id> --json` (never commit this file)")
    ap.add_argument("policy_json", help="the policy for this deployment")
    ap.add_argument("tag", help="release tag; becomes the directory name, e.g. v0.1.0-rc.33")
    ap.add_argument("--deployments", default=str(ROOT / "deployments"))
    ap.add_argument("--compose-hash", help="measured compose hash to require (default: the one in the VM description)")
    ap.add_argument("--rolled-out", help='for the changelog, e.g. "2026-11-24 18:30 UTC"')
    ap.add_argument("--changes", help="for the changelog: what changed and why")
    ap.add_argument("--os-image", help='for the changelog: the name of the OS image, e.g. "dstack-0.6.5"')
    ap.add_argument("--retire-placeholder", action="store_true",
                    help="also delete deployments/PENDING (only if it still holds its PLACEHOLDER file) and its changelog section")
    ap.add_argument("--pending", action="store_true",
                    help="publish a release whose policy is marked pending (rolled out, not yet verified live)")
    ap.add_argument("--complete", action="store_true",
                    help="replace the policy.json of an existing PENDING release with the final policy; nothing else is touched")
    ap.add_argument("--completed-on", help='for the changelog with --complete, e.g. "2026-11-25 10:00 UTC"')
    ap.add_argument("--dry-run", action="store_true", help="run every check, write nothing")
    args = ap.parse_args(argv)
    deployments = Path(args.deployments)
    if not TAG.match(args.tag):
        print("error: the tag must look like v0.1.0-rc.33", file=sys.stderr)
        return 2
    if args.complete and args.pending:
        print("error: --complete and --pending exclude each other", file=sys.stderr)
        return 2
    if args.complete and not (deployments / args.tag).is_dir():
        print("refused: %s does not exist; --complete only finishes a pending release" % (deployments / args.tag), file=sys.stderr)
        return 1
    if (deployments / args.tag).exists() and not args.complete:
        print("refused: %s already exists; published releases are never rewritten" % (deployments / args.tag), file=sys.stderr)
        return 1
    try:
        snapshot = json.loads(Path(args.cvm_json).read_text())
        policy_raw = Path(args.policy_json).read_bytes()
    except (OSError, ValueError) as exc:
        print("error: cannot read the inputs: %s" % exc, file=sys.stderr)
        return 2
    try:
        built = build(snapshot, policy_raw, args.compose_hash)
    except Refused as exc:
        for reason in exc.reasons:
            print("refused: %s" % reason, file=sys.stderr)
        print("nothing was written (%d reason%s)" % (len(exc.reasons), "" if len(exc.reasons) == 1 else "s"), file=sys.stderr)
        return 1
    facts = built["facts"]
    if bool(facts["pending"]) != args.pending and not args.complete:
        print("refused: %s" % ("the policy is marked pending; pass --pending to publish a release that is rolled out "
                               "but not yet verified live" if facts["pending"] else
                               "--pending was given but the policy is not marked pending"), file=sys.stderr)
        print("nothing was written (1 reason)", file=sys.stderr)
        return 1
    if args.complete:
        reasons = complete_release(deployments, args.tag, built, args.completed_on, args.dry_run)
        for reason in reasons:
            print("refused: %s" % reason, file=sys.stderr)
        if reasons:
            print("nothing was written (%d reason%s)" % (len(reasons), "" if len(reasons) == 1 else "s"), file=sys.stderr)
            return 1
    print("compose_hash    %s (matches the VM)" % facts["compose_hash"])
    print("COMPOSE_DIGEST  %s" % facts["compose_digest"])
    print("allowed_envs    %s" % (", ".join(facts["allowed_envs"]) or "none"))
    if facts["proxy_version"] and facts["proxy_version"] != args.tag:
        print("note: policy.proxy_version is %s, the release directory is %s" % (facts["proxy_version"], args.tag))
    if facts["pending"]:
        print("PENDING         %s" % facts["pending"])
    if args.dry_run:
        print("dry run: every check passed, nothing written")
        return 0
    if args.complete:
        print("completed %s/policy.json; the release is no longer pending" % (deployments / args.tag))
        print("next: verify/verify.py must print VERDICT: PASS, then fill in the first history entry in %s"
              % (deployments / "CHANGELOG.md"))
        return 0
    target = write_release(deployments, args.tag, built, args.rolled_out, args.changes, args.retire_placeholder, args.os_image)
    print("wrote %s/{%s}; CURRENT -> %s" % (target, ",".join(validate_deployments.REQUIRED), args.tag))
    if not (args.rolled_out and args.changes):
        print('reminder: replace "%s" in the new section of %s' % (TODO, deployments / "CHANGELOG.md"))
    if (deployments / "PENDING" / "PLACEHOLDER").exists():
        print("reminder: deployments/PENDING is still a placeholder; delete it and its changelog section "
              "(--retire-placeholder does both)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
