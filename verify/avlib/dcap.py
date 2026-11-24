"""Full Intel DCAP verification (collateral, revocation, TCB level, QE identity)
using Phala's open-source dcap-qvl (Rust, with a Python binding).

Collateral is public, Intel-signed data. It can be fetched live (Intel PCS by
default) or loaded from a file, which is what makes old history entries
re-verifiable: the recorder stores the collateral it used next to the evidence.
"""
from __future__ import annotations

import asyncio
import json

INTEL_PCS = "https://api.trustedservices.intel.com"


class DcapUnavailable(Exception):
    pass


def _lib():
    try:
        import dcap_qvl
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise DcapUnavailable("dcap-qvl is not installed (pip install -r verify/requirements.txt)") from exc
    return dcap_qvl


def fetch_collateral(raw_quote: bytes, pccs_url: str = INTEL_PCS) -> str:
    """Return collateral as a JSON string. Network access required."""
    lib = _lib()

    async def _fetch():
        # dcap-qvl's get_collateral is a native function that needs the event
        # loop to be running at the moment it is *called*, not only awaited:
        # calling it first and handing the result to asyncio.run() fails with
        # "no running event loop".
        return await lib.get_collateral(pccs_url, raw_quote)

    return asyncio.run(_fetch()).to_json()


def verify(raw_quote: bytes, collateral_json: str, at_epoch: int) -> dict:
    """Verify the quote against collateral as of `at_epoch`.

    Returns {"status", "advisory_ids", "report": {field: hex}}. Raises
    ValueError when verification fails outright (bad signature, revoked key,
    expired or not-yet-valid collateral, ...).
    """
    lib = _lib()
    collateral = lib.QuoteCollateralV3.from_json(collateral_json)
    out = json.loads(lib.verify(raw_quote, collateral, at_epoch).to_json())
    report = out.get("report", {})
    td = report.get("TD10") or (report.get("TD15") or {}).get("base") or {}
    return {
        "status": out.get("status"),
        "advisory_ids": out.get("advisory_ids", []),
        "report": {k: v for k, v in td.items() if isinstance(v, str)},
    }


def collateral_window(collateral_json: str) -> tuple[str, str]:
    """(issueDate, nextUpdate) of the TCB info inside a collateral blob."""
    tcb = json.loads(json.loads(collateral_json)["tcb_info"])
    return tcb.get("issueDate", ""), tcb.get("nextUpdate", "")
