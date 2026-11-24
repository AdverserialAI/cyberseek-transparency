#!/usr/bin/env python3
"""Check the policy that verify.adverserial.ai serves to clients, from outside.

  1. The served policy and its Sigstore bundle are byte-identical to the copies
     on the `signed` branch of the policy repository.
  2. `cosign verify-blob` accepts the served bytes for the one publishing
     identity (workflow file, branch, issuer, push trigger) with a
     transparency-log inclusion proof.
  3. The measurements in the served policy equal the ones in this repository's
     current deployment (deployments/<CURRENT>/policy.json).

Exit code 0 = all three hold, 1 = a check failed, 2 = a check could not run.
Standard library plus the `cosign` program. Read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

IDENTITY = "https://github.com/AdverserialAI/confidential-policy/.github/workflows/sign-policy.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
SITE = "https://verify.adverserial.ai"
SIGNED_RAW = "https://raw.githubusercontent.com/AdverserialAI/confidential-policy/signed"
POLICY = "policies/production.json"
BUNDLE = POLICY + ".sigstore.json"
SHARED = ("model_id", "proxy_version", "deployment_configuration_digest", "runtime_image_digest")
TDX = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "app_id", "compose_hash", "os_image_hash")


def get(url: str) -> bytes | None:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache", "User-Agent": "policy-watch"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read(1 << 20)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--site", default=SITE)
    parser.add_argument("--signed-raw", default=SIGNED_RAW, help="base URL of the policy repository's signed branch")
    parser.add_argument("--deployments", default="deployments", help="this repository's deployments directory")
    parser.add_argument("--trusted-root", help="Sigstore trusted_root.json (default: cosign's TUF-updated root)")
    args = parser.parse_args(argv)
    failed: list[str] = []
    skipped: list[str] = []

    def report(ok: bool | None, name: str, detail: str) -> None:
        print(f"[{'PASS' if ok else 'SKIP' if ok is None else 'FAIL'}] {name:<26} {detail}")
        if ok is False:
            failed.append(name)
        if ok is None:
            skipped.append(name)

    try:
        served = {name: get(f"{args.site}/{name}") for name in (POLICY, BUNDLE)}
        mirror = {name: get(f"{args.signed_raw}/{name}") for name in (POLICY, BUNDLE)}
    except OSError as exc:
        report(None, "fetch", f"network error: {exc}")
        return 2
    if served[POLICY] is None:
        report(False, "policy.served", "the site serves no production policy")
        return 1
    print(f"served policy sha256 {hashlib.sha256(served[POLICY]).hexdigest()}")
    report(served[BUNDLE] is not None, "policy.bundle_served", "a Sigstore bundle is served next to the policy" if served[BUNDLE] else f"{args.site}/{BUNDLE} does not exist: the policy is unsigned")

    if mirror[POLICY] is None or mirror[BUNDLE] is None:
        report(False, "policy.matches_signed_branch", "the policy repository's signed branch has no production policy or bundle")
    else:
        same = served[POLICY] == mirror[POLICY] and served[BUNDLE] == mirror[BUNDLE]
        report(same, "policy.matches_signed_branch", "site and signed branch are byte-identical" if same else "the site serves different bytes than the signed branch")

    if served[BUNDLE] is not None:
        with tempfile.TemporaryDirectory() as scratch:
            policy_path, bundle_path = Path(scratch) / "production.json", Path(scratch) / "production.json.sigstore.json"
            policy_path.write_bytes(served[POLICY])
            bundle_path.write_bytes(served[BUNDLE])
            command = ["cosign", "verify-blob", "--bundle", str(bundle_path), "--certificate-identity", IDENTITY, "--certificate-oidc-issuer", ISSUER,
                       "--certificate-github-workflow-trigger", "push", "--certificate-github-workflow-ref", "refs/heads/main"]
            if args.trusted_root:
                command += ["--trusted-root", args.trusted_root]
            try:
                result = subprocess.run(command + [str(policy_path)], capture_output=True, text=True, timeout=120)
                report(result.returncode == 0, "policy.signature", "signed by the publishing workflow and in the transparency log" if result.returncode == 0 else (result.stderr or result.stdout).strip()[-200:])
            except (OSError, subprocess.TimeoutExpired) as exc:
                report(None, "policy.signature", f"cosign could not run: {exc}")

    try:
        policy = json.loads(served[POLICY])
        current = next(line.strip() for line in (Path(args.deployments) / "CURRENT").read_text().splitlines() if line.strip() and not line.startswith("#"))
        deployment = json.loads((Path(args.deployments) / current / "policy.json").read_text())
    except (OSError, ValueError, StopIteration) as exc:
        report(None, "policy.matches_deployment", f"could not read the policy or the current deployment: {exc}")
    else:
        differing = [key for key in SHARED if policy.get(key) != deployment.get(key)]
        differing += ["tdx." + key for key in TDX if (policy.get("tdx") or {}).get(key) != (deployment.get("tdx") or {}).get(key)]
        if differing and deployment.get("pending"):
            # A release that is rolled out but not yet attested has no final values to compare.
            report(None, "policy.matches_deployment", f"deployments/{current} is still pending; differs in: {', '.join(differing)}")
        else:
            report(not differing, "policy.matches_deployment", f"client policy and deployments/{current} pin the same workload" if not differing else f"differs from deployments/{current} in: {', '.join(differing)}")

    print(f"\nVERDICT: {'FAIL' if failed else 'INCOMPLETE' if skipped else 'PASS'}")
    return 1 if failed else 2 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
