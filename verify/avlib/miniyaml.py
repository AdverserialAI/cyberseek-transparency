"""A small, strict reader for the YAML subset that docker compose files use.

The verifier has to know the *structure* of the published compose (which
service publishes a port, which network a service is on). A full YAML library
would be a third dependency and brings features that make a file mean
something other than what it appears to say: anchors, aliases, merge keys,
tags, multiple documents. This reader supports only

  * block mappings and block sequences, nested by indentation (spaces only),
  * plain, 'single-quoted' and "double-quoted" scalars on one line,
  * literal block scalars (`|`, `|-`, `|+`; `>` is read the same way),
  * flow collections that are also valid JSON, such as `{}` and `["a", "b"]`,
  * `#` comments,

and raises YAMLError on everything else, so a file it cannot read exactly is
rejected, never guessed at. Every scalar is returned as a string (`true` is
"true", `443` is "443"), except `null` / `~` / an empty value, which is None.
"""
from __future__ import annotations

import json
import re

_FORBIDDEN_START = "&*!%@`?<,"
_BLOCK_HEADER = re.compile(r"^[|>][+-]?(\s+#.*)?$")


class YAMLError(ValueError):
    pass


def _indent(raw: str) -> int:
    return len(raw) - len(raw.lstrip(" "))


def _is_item(s: str) -> bool:
    return s == "-" or s.startswith("- ")


def _rest_is_empty(rest: str) -> bool:
    rest = rest.strip()
    return rest == "" or rest.startswith("#")


class _Parser:
    def __init__(self, text: str):
        self.lines = text.replace("\r\n", "\n").split("\n")
        self.i = 0

    def fail(self, message: str, line: int | None = None):
        raise YAMLError("line %d: %s" % ((self.i if line is None else line) + 1, message))

    def peek(self):
        """Next significant line as (indent, text without indent), or None at the end."""
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                self.i += 1
                continue
            indent = _indent(raw)
            if raw[indent:indent + 1] == "\t":
                self.fail("tab used for indentation")
            if indent == 0 and (stripped in ("---", "...") or stripped.startswith(("--- ", "%"))):
                self.fail("document markers and directives are not supported")
            return indent, raw[indent:].rstrip()
        return None

    # -- scalars ---------------------------------------------------------
    def quoted(self, s: str) -> tuple[str, str]:
        """Parse a quoted scalar at the start of s. Returns (value, remainder)."""
        q, j = s[0], 1
        if q == '"':
            while j < len(s) and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            if j >= len(s):
                self.fail("unterminated double-quoted scalar (multi-line scalars are not supported)")
            try:
                return json.loads(s[:j + 1]), s[j + 1:]
            except ValueError:
                self.fail("double-quoted scalar uses an escape that is not valid JSON")
        out = []
        while j < len(s):
            if s[j] == "'":
                if s[j + 1:j + 2] == "'":
                    out.append("'")
                    j += 2
                    continue
                return "".join(out), s[j + 1:]
            out.append(s[j])
            j += 1
        self.fail("unterminated single-quoted scalar (multi-line scalars are not supported)")

    def scalar(self, s: str):
        s = s.strip()
        if s[0] in "\"'":
            value, rest = self.quoted(s)
            if not _rest_is_empty(rest) or (rest and not rest[0].isspace()):
                self.fail("unexpected text after a quoted scalar")
            return value
        if s[0] in "[{":
            try:
                return json.loads(s)
            except ValueError:
                self.fail("flow collections are only supported when they are valid JSON")
        if s[0] in _FORBIDDEN_START or s[0] in "|>":
            self.fail("anchors, aliases, tags, merge keys and complex keys are not supported")
        cut = s.find(" #")
        if cut >= 0:
            s = s[:cut].rstrip()
        if ": " in s or s.endswith(":"):
            self.fail("mapping value where a plain scalar was expected")
        return None if s in ("null", "~", "Null", "NULL") else s

    def split_key(self, s: str):
        """Split 'key: rest'. Returns (key, rest) or None when s is not a mapping entry."""
        if s[0] in "\"'":
            try:
                key, rest = self.quoted(s)
            except YAMLError:
                return None
            if rest == ":" or rest.startswith(": "):
                return key, rest[1:]
            return None
        m = re.search(r":(?= |$)", s)
        if not m:
            return None
        key = s[:m.start()]
        if not key or key[0] in _FORBIDDEN_START or key[0] in "|>[{#-" or " #" in key or key != key.strip():
            return None
        return key, s[m.end():]

    def block_scalar(self, header: str, parent_indent: int) -> str:
        if not _BLOCK_HEADER.match(header.strip()):
            self.fail("unsupported block scalar header %r" % header.strip(), self.i - 1)
        chomp = header.strip()[1:2]
        body, content_indent = [], None
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if raw.strip() == "":
                body.append("")
            else:
                indent = _indent(raw)
                if indent <= parent_indent:
                    break
                if content_indent is None:
                    content_indent = indent
                if indent < content_indent:
                    self.fail("block scalar line is indented less than its first line")
                if "\t" in raw[:indent + 1]:
                    self.fail("tab used for indentation")
                body.append(raw[content_indent:])
            self.i += 1
        trailing = 0
        while body and body[-1] == "":
            body.pop()
            trailing += 1
        text = "\n".join(body)
        if not body:
            return ""
        if chomp == "-":
            return text
        return text + "\n" * (1 + trailing if chomp == "+" else 1)

    # -- collections -----------------------------------------------------
    def no_continuation(self, indent: int):
        nxt = self.peek()
        if nxt and nxt[0] > indent:
            self.fail("unexpected indentation (multi-line plain scalars are not supported)")

    def value(self, rest: str, indent: int):
        """Value of a mapping entry whose key sits at `indent`; the key line is consumed."""
        if _rest_is_empty(rest):
            nxt = self.peek()
            if nxt and nxt[0] > indent:
                return self.block(nxt[0])
            if nxt and nxt[0] == indent and _is_item(nxt[1]):
                return self.sequence(indent)
            return None
        rest = rest.strip()
        if rest[0] in "|>":
            return self.block_scalar(rest, indent)
        value = self.scalar(rest)
        self.no_continuation(indent)
        return value

    def block(self, indent: int):
        return self.sequence(indent) if _is_item(self.peek()[1]) else self.mapping(indent)

    def mapping(self, indent: int) -> dict:
        out = {}
        while True:
            nxt = self.peek()
            if nxt is None or nxt[0] < indent:
                return out
            if nxt[0] > indent:
                self.fail("unexpected indentation")
            entry = None if _is_item(nxt[1]) else self.split_key(nxt[1])
            if entry is None:
                self.fail("expected 'key: value'")
            key, rest = entry
            if key in out:
                self.fail("duplicate key %r" % key)
            self.i += 1
            out[key] = self.value(rest, indent)

    def sequence(self, indent: int) -> list:
        out = []
        while True:
            nxt = self.peek()
            if nxt is None or nxt[0] < indent or (nxt[0] == indent and not _is_item(nxt[1])):
                return out
            if nxt[0] > indent:
                self.fail("unexpected indentation")
            rest = nxt[1][1:].lstrip(" ")
            column = indent + len(nxt[1]) - len(rest)
            if _rest_is_empty(rest):
                self.i += 1
                inner = self.peek()
                out.append(self.block(inner[0]) if inner and inner[0] > indent else None)
            elif rest[0] in "|>":
                self.i += 1
                out.append(self.block_scalar(rest, indent))
            elif _is_item(rest):
                self.fail("a sequence directly inside a sequence item is not supported")
            elif self.split_key(rest) is not None:
                # "- key: value": the mapping starts on the item line, at the key's column.
                self.lines[self.i] = " " * column + rest
                out.append(self.mapping(column))
            else:
                self.i += 1
                out.append(self.scalar(rest))
                self.no_continuation(indent)


def load(text: str):
    """Parse one YAML document whose top level is a mapping."""
    p = _Parser(text)
    first = p.peek()
    if first is None:
        raise YAMLError("empty document")
    if first[0] != 0 or _is_item(first[1]):
        p.fail("the top level must be a mapping that starts in the first column")
    doc = p.mapping(0)
    if p.peek() is not None:
        p.fail("unexpected content after the document")
    return doc
