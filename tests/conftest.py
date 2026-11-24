"""Shared test setup.

Private fixtures (a real attestation response, a Phala API snapshot) are never
committed. Tests that need them read their locations from environment
variables, or from an untracked tests/fixtures.local.json, and are skipped
when neither is present:

    AV_FIXTURE_ATTESTATION   saved response of /attestation
    AV_FIXTURE_CVM           Phala Cloud API JSON for the VM (contains secrets!)
    AV_FIXTURE_POLICY        the policy that was current for that attestation
    AV_FIXTURE_COLLATERAL    Intel collateral JSON for the quote (optional)
    AV_FIXTURE_COMPOSE_HASH  expected compose hash of AV_FIXTURE_CVM (optional)
    AV_FIXTURE_RELEASE_COMPOSE  docker compose of an enclave-key release (rc.31 or later)
"""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for sub in ("verify", "tools", "history", "tests"):
    sys.path.insert(0, str(ROOT / sub))

# The layout this repository had before its first release: one placeholder
# directory. Kept as test data for the placeholder rules of the tools.
PLACEHOLDER_DEPLOYMENTS = ROOT / "tests" / "data" / "placeholder-deployments"

_LOCAL = ROOT / "tests" / "fixtures.local.json"
_local = json.loads(_LOCAL.read_text()) if _LOCAL.exists() else {}


def fixture_path(name: str):
    value = os.environ.get(name) or _local.get(name)
    return Path(value) if value and Path(value).exists() else None


def fixture_value(name: str):
    return os.environ.get(name) or _local.get(name)


def require(*names):
    paths = [fixture_path(n) for n in names]
    if not all(paths):
        pytest.skip("private fixture not available: " + ", ".join(n for n, p in zip(names, paths) if not p))
    return paths if len(paths) > 1 else paths[0]


@pytest.fixture
def deployment():
    import synth
    return synth.Deployment()


@pytest.fixture
def fake_dcap(monkeypatch):
    """Stand-in for Intel collateral verification in synthetic tests (there is no real Intel signature to check)."""
    from avlib import checks, quote

    def verify(raw, collateral_json, at_epoch):
        q = quote.parse(raw)
        names = {"mrtd": "mr_td", "rtmr0": "rt_mr0", "rtmr1": "rt_mr1", "rtmr2": "rt_mr2", "rtmr3": "rt_mr3", "report_data": "report_data"}
        return {"status": json.loads(collateral_json)["status"], "advisory_ids": [], "report": {v: q.hex(k) for k, v in names.items()}}

    monkeypatch.setattr(checks.dcap, "verify", verify)
    return json.dumps({"status": "UpToDate"})
