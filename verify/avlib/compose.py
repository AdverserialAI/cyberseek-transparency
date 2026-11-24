"""Deployment configuration hashing.

compose_hash (measured by dstack into RTMR3 as the 'compose-hash' event)
-----------------------------------------------------------------------
    compose_hash = SHA-256( bytes of app-compose.json )

app-compose.json is the dstack manifest: a JSON object holding the whole
docker compose text (docker_compose_file), the pre-launch script, the list of
environment variable names the operator may set (allowed_envs) and feature
flags. The bytes that Phala Cloud hashes are the canonical serialisation:

  * keys sorted ascending,
  * compact separators ("," and ":"), no trailing newline,
  * UTF-8, non-ASCII emitted raw (as JavaScript's JSON.stringify does),
  * keys whose value is null are absent,
  * an empty "init_script" list is absent (the API view adds it as a default).

deployments/<release>/app-compose.json must be published in exactly that form,
so that `sha256sum app-compose.json` is the compose hash with no tooling.

COMPOSE_DIGEST (reported by the proxy as workload.compose_digest)
-----------------------------------------------------------------
The docker compose text contains one line `COMPOSE_DIGEST: sha256:<hex>`.
<hex> is the SHA-256 of the same text with that value replaced by the literal
`sha256:SELF`. It lets the proxy say which compose it believes it runs under;
the hardware-backed statement is still the compose_hash above.
"""
from __future__ import annotations

import hashlib
import json
import re

from . import miniyaml, secretscan

SELF = "sha256:SELF"
_DIGEST_LINE = re.compile(r"COMPOSE_DIGEST\s*[:=]\s*[\"']?(sha256:[0-9a-f]{64}|sha256:SELF)")
_IMAGE = re.compile(r"^\s*image:\s*[\"']?([^\s\"'#]+)", re.M)
# Variables through which rc.30 and earlier let the operator choose key
# material or hold the proxy-to-inference credential. From v0.1.0-rc.31 (first
# deployed: v0.1.0-rc.33) the proxy refuses to start in CONFIDENTIAL_MODE when
# any of them is set (attest-proxy internal/config/config.go, ExternalSecretEnv).
DEFAULT_OPERATOR_KEY_ENVS = ("RECEIPT_SIGNING_SEED", "METER_SIGNING_SEED", "EHBP_IDENTITY_B64", "UPSTREAM_BEARER_TOKEN")
# What the proxy must be given instead: where it keeps the keys it generates,
# and the file from which it reads the credential generated inside the VM.
REQUIRED_PROXY_PATH_ENVS = ("ENCLAVE_KEY_DIR", "UPSTREAM_BEARER_TOKEN_FILE")
DEFAULT_PROXY_SERVICE, DEFAULT_INFERENCE_SERVICE = "attest-proxy", "sglang"
PROVENANCE_COMMAND = "gh attestation verify oci://ghcr.io/adverserialai/attest-proxy@%s -R AdverserialAI/attest-proxy"
_PINNED = re.compile(r"@(sha256:[0-9a-f]{64})$")
_NAME = r"[A-Za-z_][A-Za-z0-9_]*"


class ComposeViolation(Exception):
    """The published compose does not have a property the verifier requires."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_app_compose(obj: dict) -> bytes:
    """Canonical bytes of an app-compose object (see module docstring)."""
    cleaned = {k: v for k, v in obj.items() if v is not None and not (k == "init_script" and v == [])}
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def app_compose_hash(raw: bytes) -> tuple[str, str]:
    """Return (hash of the bytes as published, hash of their canonical form)."""
    try:
        canonical = sha256_hex(canonical_app_compose(json.loads(raw)))
    except (ValueError, AttributeError):
        canonical = ""
    return sha256_hex(raw), canonical


def self_digest(compose_text: str) -> tuple[str, str]:
    """Return (digest declared in the text, digest recomputed from the text)."""
    declared = set(_DIGEST_LINE.findall(compose_text))
    if len(declared) != 1:
        raise ValueError("expected exactly one COMPOSE_DIGEST value, found %d" % len(declared))
    value = declared.pop()
    normalised = _DIGEST_LINE.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + SELF, compose_text)
    return value, "sha256:" + sha256_hex(normalised.encode("utf-8"))


def images(compose_text: str) -> list[str]:
    seen = []
    for ref in _IMAGE.findall(compose_text):
        if ref not in seen:
            seen.append(ref)
    return seen


def unpinned_images(compose_text: str) -> list[str]:
    return [ref for ref in images(compose_text) if not re.search(r"@sha256:[0-9a-f]{64}$", ref)]


# ---- structure -------------------------------------------------------------
def load(compose_text: str) -> dict:
    """Parse the compose with the strict reader and reject what could change its meaning from outside."""
    try:
        doc = miniyaml.load(compose_text)
    except miniyaml.YAMLError as exc:
        raise ComposeViolation("the compose cannot be read by the strict YAML reader (%s)" % exc) from None
    services = doc.get("services")
    if not isinstance(services, dict) or not services or not all(isinstance(v, dict) for v in services.values()):
        raise ComposeViolation("the compose has no services mapping")
    if "include" in doc:
        raise ComposeViolation("the compose uses 'include', which pulls in configuration from outside the measured file")
    for name, svc in services.items():
        for key in ("extends", "env_file"):
            if key in svc:
                raise ComposeViolation("service %s uses '%s', which pulls in configuration from outside the measured file" % (name, key))
    return doc


def service_env(svc: dict) -> dict:
    """{NAME: value} of a service. A name passed through from the host has the value None."""
    env = svc.get("environment")
    if env is None:
        return {}
    if isinstance(env, dict):
        return {str(k): v for k, v in env.items()}
    if isinstance(env, list):
        out = {}
        for item in env:
            name, sep, value = str(item).partition("=")
            out[name] = value if sep else None
        return out
    raise ComposeViolation("a service's environment is neither a mapping nor a list")


def interpolations(value: str) -> list[str]:
    """Variable names docker compose would substitute in this string. "$$" is a literal dollar sign."""
    out, i = [], 0
    while i < len(value):
        if value[i] != "$":
            i += 1
        elif value[i + 1:i + 2] == "$":
            i += 2
        else:
            m = re.match(r"\$(?:\{(%s)|(%s))" % (_NAME, _NAME), value[i:])
            if m:
                out.append(m.group(1) or m.group(2))
            i += 1
    return out


def _walk(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(k, path + ("<key>",))
            yield from _walk(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (i,))
    elif isinstance(node, str):
        yield path, node


def sealed_references(doc: dict) -> set[str]:
    """Names whose values the operator supplies at deploy time (unmeasured).

    The only accepted use is a service environment variable whose whole value
    is `${NAME}` (or a bare name passed through). Substitution anywhere else,
    for example in an image, a port, a volume or a command, would let an
    unmeasured value change what the measured file means.
    """
    names, misplaced = set(), []
    for path, value in _walk(doc):
        found = interpolations(value)
        if not found:
            continue
        in_env = len(path) == 4 and path[0] == "services" and path[2] == "environment" and path[3] != "<key>"
        whole = re.fullmatch(r"(?:%s=)?\$\{(%s)\}" % (_NAME, _NAME), value) if isinstance(path[-1], int) \
            else re.fullmatch(r"\$\{(%s)\}" % _NAME, value)
        if in_env and whole:
            names.add(whole.group(1))
        else:
            misplaced.append(".".join(str(x) for x in path))
    for svc in doc["services"].values():
        names |= {name for name, value in service_env(svc).items() if value is None}
    if misplaced:
        raise ComposeViolation("deploy-time substitution outside a plain environment value: %s" % ", ".join(sorted(set(misplaced))))
    return names


def _service(doc: dict, name: str) -> dict:
    if name not in doc["services"]:
        raise ComposeViolation("the compose has no service named %s" % name)
    return doc["services"][name]


def service_networks(svc: dict) -> list[str]:
    nets = svc.get("networks")
    if nets is None:
        return [] if "network_mode" in svc else ["default"]
    return [str(n) for n in nets]


def image_digest(svc: dict) -> str | None:
    m = _PINNED.search(str(svc.get("image") or ""))
    return m.group(1) if m else None


def check_images(doc: dict) -> list[str]:
    """Every service runs an image pinned by sha256 digest; nothing is built on the spot."""
    refs = []
    for name, svc in doc["services"].items():
        if "build" in svc:
            raise ComposeViolation("service %s is built from a Dockerfile inside the VM, not pulled by digest" % name)
        if not image_digest(svc):
            raise ComposeViolation("service %s image is not pinned by sha256 digest: %s" % (name, svc.get("image")))
        if svc["image"] not in refs:
            refs.append(svc["image"])
    return refs


def check_inference_isolated(doc: dict, inference: str, proxy: str) -> str:
    """The model server can be reached only from the proxy, over a network with no route out of the VM."""
    svc = _service(doc, inference)
    if "network_mode" in svc:
        raise ComposeViolation("%s sets network_mode: %s" % (inference, svc["network_mode"]))
    if svc.get("ports"):
        raise ComposeViolation("%s publishes ports" % inference)
    if "networks" not in svc or not service_networks(svc):
        raise ComposeViolation("%s does not name its networks, so it would join the default (routable) network" % inference)
    declared = doc.get("networks") or {}
    for net in service_networks(svc):
        if not isinstance(declared.get(net), dict) or str(declared[net].get("internal")).lower() != "true":
            raise ComposeViolation("%s is attached to network %s, which is not declared internal: true" % (inference, net))
        others = sorted(n for n, s in doc["services"].items() if n not in (inference, proxy) and net in service_networks(s))
        if others:
            raise ComposeViolation("network %s is shared with services other than the proxy: %s" % (net, ", ".join(others)))
    return "%s publishes no ports, sets no network_mode and is attached only to %s (internal: true), shared only with %s" % (
        inference, ", ".join(service_networks(svc)), proxy)


def check_single_ingress(doc: dict, proxy: str) -> str:
    """The proxy is the only container reachable from outside the VM."""
    _service(doc, proxy)
    for name, svc in doc["services"].items():
        mode = svc.get("network_mode")
        if mode not in (None, "none", "bridge"):
            raise ComposeViolation("service %s uses network_mode: %s (host or another container's network)" % (name, mode))
        if name != proxy and svc.get("ports"):
            raise ComposeViolation("service %s publishes ports; only %s may" % (name, proxy))
    ports = doc["services"][proxy].get("ports") or []
    if not ports:
        raise ComposeViolation("%s publishes no port" % proxy)
    shown = ", ".join("%s->%s" % (p.get("published"), p.get("target")) if isinstance(p, dict) else str(p) for p in ports)
    return "only %s publishes ports (%s); no service uses host or shared-container networking" % (proxy, shown)


def check_sealed_envs(doc: dict, app_allowed, policy_allowed) -> str:
    """The operator-supplied variables are exactly the ones the policy lists."""
    used = sealed_references(doc)
    app_allowed, policy_allowed = set(app_allowed or []), set(policy_allowed)
    if not used == app_allowed == policy_allowed:
        raise ComposeViolation("operator-supplied variables differ: compose references [%s], app-compose allowed_envs [%s], policy verifier.allowed_envs [%s]" % (
            ", ".join(sorted(used)), ", ".join(sorted(app_allowed)), ", ".join(sorted(policy_allowed))))
    return "operator-supplied (unmeasured) variables, each used only as a whole environment value: %s" % (", ".join(sorted(used)) or "none")


def check_keys_in_enclave(doc: dict, compose_text: str, app_allowed, proxy: str, banned, trusted_digests, policy_proxy_digest) -> str:
    """The published configuration is one under which the proxy generates its own keys."""
    svc = _service(doc, proxy)
    env = service_env(svc)
    banned = tuple(dict.fromkeys(tuple(DEFAULT_OPERATOR_KEY_ENVS) + tuple(banned or ())))
    seen = set(app_allowed or []) | sealed_references(doc)
    for other in doc["services"].values():
        seen |= set(service_env(other))
    hit = sorted(n for n in seen if n in banned)
    if hit:
        raise ComposeViolation("the compose lets the operator supply key material or the upstream credential via: %s" % ", ".join(hit))
    for name in REQUIRED_PROXY_PATH_ENVS:
        value = env.get(name)
        if not isinstance(value, str) or not value.startswith("/") or interpolations(value):
            raise ComposeViolation("%s does not set %s to a fixed absolute path" % (proxy, name))
    if str(env.get("CONFIDENTIAL_MODE", "")).lower() not in ("1", "true"):
        raise ComposeViolation("%s does not set CONFIDENTIAL_MODE=1; only confidential mode refuses operator-supplied keys" % proxy)
    digest = image_digest(svc)
    if not digest:
        raise ComposeViolation("%s image is not pinned by digest" % proxy)
    if policy_proxy_digest and digest != policy_proxy_digest:
        raise ComposeViolation("%s image %s is not the policy's proxy_image_digest %s" % (proxy, digest, policy_proxy_digest))
    if digest not in (trusted_digests or ()):
        raise ComposeViolation("%s image %s is not listed in the policy (verifier.enclave_key_proxy_digests) as a build that refuses operator-supplied keys" % (proxy, digest))
    findings = secretscan.scan_text(compose_text)
    if findings:
        raise ComposeViolation("the compose contains %d value(s) that look like literal credentials (line %s)" % (
            len(findings), ", ".join(str(n) for n in sorted({n for n, _, _ in findings}))))
    return ("%s sets %s and CONFIDENTIAL_MODE, none of %s is set or injectable, no literal credential in the compose; "
            "image %s is listed as built from source that refuses those variables. Confirm that yourself: %s" % (
                proxy, ", ".join(REQUIRED_PROXY_PATH_ENVS), ", ".join(banned), digest, PROVENANCE_COMMAND % digest))
