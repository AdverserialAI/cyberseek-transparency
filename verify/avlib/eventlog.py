"""dstack event-log replay (dstack 0.5.x and 0.6.x, event log V1).

Each RTMR starts as 48 zero bytes and is extended as
    rtmr = SHA-384(rtmr || event_digest)

For RTMR3 (the runtime lane written by dstack) every event digest is itself
recomputable from the event's name and payload:
    digest = SHA-384(le32(event_type) || ":" || event_name || ":" || payload)
so the app id, compose hash, OS image hash and key provider are tied to the
signed quote. RTMR0-2 events (firmware, kernel, initrd) only carry digests;
they are replayed too, and the resulting values are compared with the quote.

RTMR3 event order, as written by the guest OS:

  dstack 0.5.x  system-preparing, app-id, compose-hash, instance-id,
                boot-mr-done, os-image-hash, key-provider, system-ready
  dstack 0.6.x  system-preparing, app-id, compose-hash, [init-script-hash...],
                gpu-policy-hash, instance-id, boot-mr-done, os-image-hash,
                key-provider, [gpu-attestation], storage-fs,
                storage-encrypted, system-ready

`gpu-policy-hash` is SHA-256 of the canonical (RFC 8785) form of the
manifest's `requirements.gpu_policy`. `gpu-attestation` is written only when
the OS itself attested the GPUs before releasing keys; with
`"attest_gpu": false` in the policy there is no such event. Both are optional
(0.5.x has neither), but when present they must be unique and inside the same
boundaries as the other trusted events, so that an application cannot add one
after boot.

Mirrors verifyTDXWorkload in the client kit (tdx-workload.js).
"""
from __future__ import annotations

import hashlib
import json
import struct

RUNTIME_EVENT_TYPE = 0x08000001
BEFORE_BOOT_DONE = ("app-id", "compose-hash", "instance-id")
BEFORE_READY = ("os-image-hash", "key-provider")
# Written by dstack 0.6.x only. Absent is fine; present means exactly once and inside the boundary.
OPTIONAL_BEFORE_BOOT_DONE = ("gpu-policy-hash",)
OPTIONAL_BEFORE_READY = ("gpu-attestation",)


class EventLogError(Exception):
    pass


def load(event_log) -> list:
    events = json.loads(event_log) if isinstance(event_log, str) else event_log
    if not isinstance(events, list) or not events or len(events) > 4096:
        raise EventLogError("invalid TDX event log")
    return events


def _hex(s, what) -> bytes:
    try:
        return bytes.fromhex(s)
    except (TypeError, ValueError):
        raise EventLogError("invalid hex in %s" % what) from None


def runtime_digest(event: dict) -> bytes:
    name, payload = event.get("event"), event.get("event_payload")
    if (event.get("event_type") != RUNTIME_EVENT_TYPE or not isinstance(name, str)
            or not name or len(name) > 256 or not isinstance(payload, str)):
        raise EventLogError("unsupported RTMR3 runtime event format")
    return hashlib.sha384(struct.pack("<I", RUNTIME_EVENT_TYPE) + b":" + name.encode() + b":"
                          + _hex(payload, "event payload")).digest()


def replay(events: list) -> dict:
    """Return {0..3: rtmr hex}. RTMR3 digests are recomputed from payloads."""
    mrs = {i: bytes(48) for i in range(4)}
    for e in events:
        if not isinstance(e, dict) or e.get("imr") not in mrs:
            raise EventLogError("event with an unknown measurement register")
        imr = e["imr"]
        if imr == 3:
            digest = runtime_digest(e)
            if e.get("digest") and e["digest"].lower() != digest.hex():
                raise EventLogError("RTMR3 event '%s' digest does not match its payload" % e.get("event"))
        else:
            digest = _hex(e.get("digest"), "event digest")
            if len(digest) != 48:
                raise EventLogError("event digest is not SHA-384")
        mrs[imr] = hashlib.sha384(mrs[imr] + digest).digest()
    return {i: v.hex() for i, v in mrs.items()}


def runtime_facts(events: list) -> dict:
    """Validate RTMR3 ordering and return {event name: payload hex}.

    Trusted facts must be recorded exactly once and inside the boot boundary,
    so that a compromised application cannot append a second 'compose-hash'.
    """
    lane = [e for e in events if e.get("imr") == 3]
    if not lane:
        raise EventLogError("the event log has no RTMR3 events")

    def one(name):
        found = [e for e in lane if e.get("event") == name]
        if len(found) != 1:
            raise EventLogError("missing or duplicate trusted event: %s" % name)
        return found[0]

    preparing, boot, ready = one("system-preparing"), one("boot-mr-done"), one("system-ready")
    if lane[0] is not preparing or lane.index(boot) >= lane.index(ready):
        raise EventLogError("invalid boot event ordering")
    for name in BEFORE_BOOT_DONE:
        if lane.index(one(name)) >= lane.index(boot):
            raise EventLogError("%s was recorded outside the trusted boot boundary" % name)
    for name in BEFORE_READY:
        if lane.index(one(name)) >= lane.index(ready):
            raise EventLogError("%s was recorded outside the trusted system boundary" % name)
    for names, boundary, what in ((OPTIONAL_BEFORE_BOOT_DONE, boot, "boot"), (OPTIONAL_BEFORE_READY, ready, "system")):
        for name in names:
            if any(e.get("event") == name for e in lane) and lane.index(one(name)) >= lane.index(boundary):
                raise EventLogError("%s was recorded outside the trusted %s boundary" % (name, what))
    facts = {e["event"]: e["event_payload"] for e in lane}
    after_ready = [e["event"] for e in lane[lane.index(ready) + 1:]]
    facts["_events_after_system_ready"] = after_ready
    return facts
