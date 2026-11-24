"""Network access for the verifier, standard library only.

`Endpoint.get` returns the response body together with the SHA-256 of the
SubjectPublicKeyInfo of the certificate presented on that very connection, so
the TLS key that actually served the evidence can be compared with the key the
enclave attested.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import urllib.parse
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .canonjson import b64url

USER_AGENT = "adverserial-verify/1"
MAX_BODY = 8 * 1024 * 1024


class FetchError(Exception):
    pass


class Endpoint:
    def __init__(self, base_url: str, timeout: float = 30.0):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme != "https" or not u.hostname:
            raise FetchError("endpoint must be an https:// URL")
        self.host, self.port, self.timeout = u.hostname, u.port or 443, timeout
        self.spki_seen: list[str] = []

    def get(self, path: str) -> tuple[int, bytes, str]:
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                           context=ssl.create_default_context())
        try:
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True)
            spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            spki_hash = "sha256:" + b64url(hashlib.sha256(spki).digest())
            self.spki_seen.append(spki_hash)
            conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            resp = conn.getresponse()
            body = resp.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise FetchError("response from %s is too large" % path)
            return resp.status, body, spki_hash
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise FetchError("request to https://%s%s failed: %s" % (self.host, path, exc)) from None
        finally:
            conn.close()


def read_source(source: str) -> bytes:
    """Read a local path or an https:// URL."""
    if source.startswith("https://"):
        req = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read(MAX_BODY)
        except OSError as exc:
            raise FetchError("could not fetch %s: %s" % (source, exc)) from None
    if source.startswith("http://"):
        raise FetchError("refusing to read %s over plain http" % source)
    with open(source, "rb") as fh:
        return fh.read()


def read_json(source: str):
    return json.loads(read_source(source))
