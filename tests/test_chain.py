import json

import pytest

import chainlib


def make(tmp_path, n=3):
    path = tmp_path / "history" / "attestations.jsonl"
    for i in range(n):
        chainlib.append(path, {"timestamp": "2030-01-01T00:0%d:00Z" % i, "verdict": "PASS"})
    return path


def test_append_links_each_line_to_the_previous(tmp_path):
    path = make(tmp_path)
    lines = chainlib.read_lines(path)
    entries = [json.loads(line) for line in lines]
    assert [e["seq"] for e in entries] == [0, 1, 2]
    assert entries[0]["prev"] == chainlib.GENESIS
    assert entries[1]["prev"] == chainlib.line_hash(lines[0]) and entries[2]["prev"] == chainlib.line_hash(lines[1])
    assert chainlib.validate(path) == (3, chainlib.line_hash(lines[2]))


def test_empty_or_missing_history_is_valid(tmp_path):
    assert chainlib.validate(tmp_path / "nope.jsonl") == (0, chainlib.GENESIS)
    (tmp_path / "empty.jsonl").write_bytes(b"")
    assert chainlib.validate(tmp_path / "empty.jsonl") == (0, chainlib.GENESIS)


@pytest.mark.parametrize("tamper", ["edit", "delete", "swap", "reformat", "truncate", "insert"])
def test_any_rewrite_is_detected(tmp_path, tamper):
    path = make(tmp_path, 4)
    lines = chainlib.read_lines(path)
    if tamper == "edit":
        lines[1] = lines[1].replace(b'"PASS"', b'"FAIL"')
    elif tamper == "delete":
        del lines[1]
    elif tamper == "swap":
        lines[1], lines[2] = lines[2], lines[1]
    elif tamper == "reformat":
        lines[0] = json.dumps(json.loads(lines[0])).encode()
    elif tamper == "insert":
        forged = dict(json.loads(lines[1]), verdict="FAIL")
        lines.insert(2, chainlib.encode(forged))
    data = b"\n".join(lines) + b"\n"
    if tamper == "truncate":
        data = data[:-5]
    path.write_bytes(data)
    with pytest.raises(chainlib.ChainError):
        chainlib.validate(path)


def test_removing_the_last_line_changes_the_head(tmp_path):
    path = make(tmp_path, 3)
    _, head = chainlib.validate(path)
    lines = chainlib.read_lines(path)
    path.write_bytes(b"\n".join(lines[:-1]) + b"\n")
    count, new_head = chainlib.validate(path)  # still a valid chain ...
    assert count == 2 and new_head != head      # ... but not the head that was timestamped


def test_timestamps_must_not_go_backwards(tmp_path):
    path = tmp_path / "h.jsonl"
    chainlib.append(path, {"timestamp": "2030-01-02T00:00:00Z"})
    chainlib.append(path, {"timestamp": "2030-01-01T00:00:00Z"})
    with pytest.raises(chainlib.ChainError, match="timestamp"):
        chainlib.validate(path)


def test_stored_files_are_rehashed(tmp_path):
    blob = tmp_path / "history" / "evidence" / "e.json"
    blob.parent.mkdir(parents=True)
    blob.write_bytes(b"{}")
    path = tmp_path / "history" / "attestations.jsonl"
    chainlib.append(path, {"timestamp": "t", "files": {"evidence": {"path": "history/evidence/e.json", "sha256": chainlib.line_hash(b"{}")}}})
    assert chainlib.validate(path, tmp_path)[0] == 1
    blob.write_bytes(b"{ }")
    with pytest.raises(chainlib.ChainError, match="modified"):
        chainlib.validate(path, tmp_path)
    blob.unlink()
    with pytest.raises(chainlib.ChainError, match="missing"):
        chainlib.validate(path, tmp_path)


def test_file_references_cannot_escape_the_repository(tmp_path):
    path = tmp_path / "history" / "attestations.jsonl"
    chainlib.append(path, {"timestamp": "t", "files": {"evidence": {"path": "../outside", "sha256": "00"}}})
    with pytest.raises(chainlib.ChainError, match="outside"):
        chainlib.validate(path, tmp_path)


def test_append_only_predicate():
    old = b'{"a":1}\n'
    assert chainlib.is_append_only(old, old)
    assert chainlib.is_append_only(old, old + b'{"b":2}\n')
    assert chainlib.is_append_only(b"", old)
    assert not chainlib.is_append_only(old, b'{"a":2}\n{"b":2}\n')
    assert not chainlib.is_append_only(old, b"")
    assert not chainlib.is_append_only(old, old + b'{"b":2}')
