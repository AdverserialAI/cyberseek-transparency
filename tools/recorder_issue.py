#!/usr/bin/env python3
"""Report the scheduled recorder's outcome in ONE GitHub issue, without noise.

    python tools/recorder_issue.py --code 5 --record record.json --run-url <url>

The recorder runs every 30 minutes. A condition that lasts for days (the
endpoint is down, the policy is still pending) must not produce a new issue,
or a new comment, every half hour. The rules:

  * There is at most one open issue with the label `attestation-failure`.
    If several exist, the oldest is used.
  * Nothing is wrong and no issue is open: do nothing.
  * Something is wrong and no issue is open: open one.
  * The same thing is still wrong: rewrite the issue body (first seen, last
    seen, number of consecutive runs, the latest history entry). No comment,
    so nobody is notified again.
  * Something different is wrong: retitle, rewrite the body, and add one
    comment naming the change.
  * The recorder is back to PASS: add one comment. The issue is closed
    automatically only if it was about reachability or a pending policy; an
    issue about a failed or incomplete verification, or about measurements
    that match no release, stays open until a person has looked at it.

The history itself is never affected by any of this: every run, good or bad,
is one line in history/attestations.jsonl.

The state is kept in an HTML comment at the top of the issue body. Values that
come from the endpoint (the error text) are stripped of backticks and "@"
before they are written into an issue.

With --dry-run the planned `gh` commands are printed as JSON and nothing is
sent. Needs the `gh` CLI and GH_TOKEN otherwise.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

LABEL = "attestation-failure"
KINDS = {
    1: ("failed", "Verification FAILED"),
    2: ("incomplete", "Verification INCOMPLETE (a check could not run)"),
    4: ("unmatched", "Measurements match no release under deployments/"),
    5: ("unreachable", "Endpoint unreachable"),
    6: ("pending", "Endpoint is answering, but the policy of the current release is still pending"),
}
ERROR = ("error", "Recorder or workflow error")
# Conditions that end by themselves and need no post-mortem in the issue tracker.
AUTO_CLOSE = ("unreachable", "pending")
ADVICE = {
    "unreachable": "The endpoint did not return a usable attestation. Each attempt is recorded as an `UNREACHABLE` line in "
                   "`history/attestations.jsonl`. This issue closes itself when the recorder verifies the endpoint again.",
    "pending": "The endpoint answers and nothing failed, but `deployments/CURRENT` names a release whose `policy.json` is still "
               "marked pending, so the verdict is `INCOMPLETE` by design. Complete the policy (`deployments/README.md`, "
               "\"Completing a pending release\"). The recorder records `PASS` by itself from the next run on, and this issue "
               "closes itself.",
    "failed": "At least one property is false. Treat the endpoint as untrusted until this is understood.",
    "incomplete": "Nothing failed, but a check could not run, so nothing was proven for that property.",
    "unmatched": "The endpoint runs something that no directory under `deployments/` describes. A legitimate upgrade is "
                 "published there first.",
    "error": "The recorder or the workflow itself failed; no conclusion about the endpoint can be drawn from this run.",
}
STATE = re.compile(r"<!-- recorder-state: (\{.*?\}) -->")
SHOWN = ("timestamp", "verdict", "failed", "skipped", "policy_state", "deployment", "expected_deployment", "pending_deployment",
         "measurements_changed", "compose_hash", "os_image_hash", "error")


def clean(value):
    """No mentions and no code-fence breakouts from endpoint-controlled text."""
    if isinstance(value, str):
        return value.replace("`", "").replace("@", "")
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def read_state(body: str | None) -> dict:
    match = STATE.search(body or "")
    try:
        state = json.loads(match.group(1)) if match else {}
    except ValueError:
        state = {}
    return state if isinstance(state, dict) else {}


def classify(code) -> tuple[str, str]:
    try:
        code = int(code)
    except (TypeError, ValueError):
        return ERROR
    if code == 0:
        return "ok", "Verified"
    return KINDS.get(code, (ERROR[0], "%s (exit %d)" % (ERROR[1], code)))


def body_for(kind: str, reason: str, state: dict, entry: dict | None, run_url: str) -> str:
    shown = {k: clean(entry.get(k)) for k in SHOWN if entry and k in entry}
    return "\n".join([
        "<!-- recorder-state: %s -->" % json.dumps(state, sort_keys=True, separators=(",", ":")),
        "**%s.**" % reason,
        "",
        ADVICE[kind],
        "",
        "| | |",
        "|---|---|",
        "| First seen | %s (history seq %s) |" % (state.get("since") or "unknown", state.get("since_seq")),
        "| Last seen | %s (history seq %s) |" % (state.get("last") or "unknown", state.get("last_seq")),
        "| Consecutive runs | %d |" % state.get("runs", 1),
        "| Latest run | %s |" % run_url,
        "",
        "Latest history entry (this body is rewritten on every run; no comment is added while the condition is unchanged):",
        "",
        "```json",
        json.dumps(shown, indent=2) if shown else '"no history entry was written"',
        "```",
        ""])


def plan(existing: dict | None, code, entry: dict | None, run_url: str = "") -> list[dict]:
    """What to do, as a list of actions. Pure: no network, no clock."""
    kind, reason = classify(code)
    stamp = (entry or {}).get("timestamp")
    seq = (entry or {}).get("seq")
    old = read_state(existing.get("body")) if existing else {}
    if kind == "ok":
        if not existing or old.get("recovered"):
            return []
        note = "The recorder verified the endpoint again at %s (history seq %s). Run: %s" % (stamp, seq, run_url)
        if old.get("kind") in AUTO_CLOSE:
            return [{"do": "close", "number": existing["number"], "comment": note}]
        state = dict(old, recovered=stamp or True)
        body = STATE.sub(lambda m: "<!-- recorder-state: %s -->" % json.dumps(state, sort_keys=True, separators=(",", ":")),
                         existing.get("body") or "", count=1)
        if not STATE.search(existing.get("body") or ""):
            body = "<!-- recorder-state: %s -->\n%s" % (json.dumps(state, sort_keys=True, separators=(",", ":")), existing.get("body") or "")
        return [{"do": "edit", "number": existing["number"], "title": existing.get("title"), "body": body},
                {"do": "comment", "number": existing["number"],
                 "body": note + "\n\nThis issue stays open until someone has looked at what happened and closes it."}]
    title = "Attestation recorder: %s" % reason
    same = bool(existing) and old.get("kind") == kind and not old.get("recovered")
    state = {"kind": kind, "since": old.get("since") if same else stamp, "since_seq": old.get("since_seq") if same else seq,
             "last": stamp, "last_seq": seq, "runs": int(old.get("runs", 0)) + 1 if same else 1}
    body = body_for(kind, reason, state, entry, run_url)
    if not existing:
        return [{"do": "create", "title": title, "body": body}]
    actions = [{"do": "edit", "number": existing["number"], "title": title, "body": body}]
    if not same:
        before = old.get("kind") or "an earlier report"
        actions.append({"do": "comment", "number": existing["number"],
                        "body": "The recorder's state changed from **%s** to **%s** at %s (history seq %s). Run: %s"
                                % (before + (" (recovered)" if old.get("recovered") else ""), kind, stamp, seq, run_url)})
    return actions


def gh(*args, stdin: str | None = None) -> str:
    done = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True)
    if done.returncode != 0:
        raise RuntimeError("gh %s failed: %s" % (args[0:2], done.stderr.strip()))
    return done.stdout


def apply(actions: list[dict]) -> None:
    for a in actions:
        if a["do"] == "create":
            subprocess.run(["gh", "label", "create", LABEL, "--color", "B60205", "--description",
                            "The scheduled recorder reported a problem"], capture_output=True)   # exists already: fine
            gh("issue", "create", "--title", a["title"], "--label", LABEL, "--body-file", "-", stdin=a["body"])
        elif a["do"] == "edit":
            gh("issue", "edit", str(a["number"]), "--title", a["title"], "--body-file", "-", stdin=a["body"])
        elif a["do"] == "comment":
            gh("issue", "comment", str(a["number"]), "--body-file", "-", stdin=a["body"])
        elif a["do"] == "close":
            gh("issue", "close", str(a["number"]), "--comment", a["comment"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--code", default="", help="exit code of history/record.py (empty when it did not finish)")
    ap.add_argument("--record", default="record.json", help="the recorder's JSON output")
    ap.add_argument("--run-url", default="")
    ap.add_argument("--existing", help="read the open issue from this JSON file instead of asking gh (for --dry-run)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        entry = json.loads(Path(args.record).read_text())["entry"]
    except (OSError, ValueError, KeyError, TypeError):
        entry = None
    if args.existing:
        existing = json.loads(Path(args.existing).read_text())
    else:
        found = json.loads(gh("issue", "list", "--label", LABEL, "--state", "open", "--limit", "100", "--json", "number,title,body"))
        existing = min(found, key=lambda i: i["number"]) if found else None
    actions = plan(existing, args.code, entry if isinstance(entry, dict) else None, args.run_url)
    if args.dry_run:
        print(json.dumps(actions, indent=2))
    else:
        apply(actions)
        print("recorder issue: %s" % (", ".join(a["do"] for a in actions) or "nothing to do"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
