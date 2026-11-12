"""Tamper-resistance tests for ChainProof audit log.

Each test builds a small case, applies one attack, and asserts whether
verification detects it. Truncation of trailing entries is a known
limitation: it leaves a valid chain, so that test documents the behavior
rather than asserting failure.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.hashing import hash_file
from modules.signing import generate_keypair, load_private_key, load_public_key
from modules.auditlog import AuditLog, GENESIS_PREV_HASH


@pytest.fixture
def case_dir():
    tmp = Path(tempfile.mkdtemp(prefix="chainproof_test_"))
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


def init_case(tmp, actor="analyst"):
    case_dir = tmp / "case"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "logs").mkdir(parents=True)
    (case_dir / "reports").mkdir(parents=True)
    (case_dir / "keys").mkdir(parents=True)
    generate_keypair(case_dir, key_dir=case_dir / "keys")
    priv = load_private_key(case_dir, key_dir=case_dir / "keys")
    log = AuditLog(case_dir)
    log.genesis(actor=actor, private_key=priv)
    return case_dir


def add_evidence(case_dir, name, content):
    ev_path = case_dir / "evidence" / name
    ev_path.write_bytes(content)
    digest = hash_file(ev_path)
    priv = load_private_key(case_dir, key_dir=case_dir / "keys")
    log = AuditLog(case_dir)
    log.append("EVIDENCE_ADDED", "analyst", evidence=digest, private_key=priv)
    return ev_path, digest


def write_log(case_dir, entries):
    """Overwrite the log file with raw JSONL entries."""
    log_path = case_dir / "logs" / "audit.jsonl"
    with log_path.open("w") as fh:
        for e in entries:
            fh.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")


def load_entries(case_dir):
    log = AuditLog(case_dir)
    return log.entries


def test_chain_verifies_when_untouched(case_dir):
    case_dir = init_case(case_dir)
    add_evidence(case_dir, "a.txt", b"hello")
    add_evidence(case_dir, "b.txt", b"world")
    log = AuditLog(case_dir)
    ok, message = log.verify(
        public_key=load_public_key(case_dir, key_dir=case_dir / "keys")
    )
    assert ok is True, message


def test_edit_entry_detected(case_dir):
    case_dir = init_case(case_dir)
    add_evidence(case_dir, "a.txt", b"hello")
    entries = load_entries(case_dir)
    # Flip the action on entry 1.
    entries[1]["action"] = "TAMPERED"
    write_log(case_dir, entries)
    log = AuditLog(case_dir)
    ok, message = log.verify(
        public_key=load_public_key(case_dir, key_dir=case_dir / "keys")
    )
    assert ok is False
    assert "hash mismatch" in message or "signature invalid" in message


def test_delete_middle_entry_detected(case_dir):
    case_dir = init_case(case_dir)
    add_evidence(case_dir, "a.txt", b"hello")
    add_evidence(case_dir, "b.txt", b"world")
    entries = load_entries(case_dir)
    # Remove entry index 1 (the first evidence add).
    entries = [e for e in entries if e["index"] != 1]
    write_log(case_dir, entries)
    log = AuditLog(case_dir)
    ok, message = log.verify(
        public_key=load_public_key(case_dir, key_dir=case_dir / "keys")
    )
    assert ok is False


def test_truncation_leaves_valid_chain(case_dir):
    """Known limitation: deleting trailing entries keeps a valid chain."""
    case_dir = init_case(case_dir)
    add_evidence(case_dir, "a.txt", b"hello")
    add_evidence(case_dir, "b.txt", b"world")
    entries = load_entries(case_dir)
    # Drop the last entry.
    entries = entries[:-1]
    write_log(case_dir, entries)
    log = AuditLog(case_dir)
    ok, message = log.verify(
        public_key=load_public_key(case_dir, key_dir=case_dir / "keys")
    )
    assert ok is True, message  # documented limitation


def test_reorder_entries_detected(case_dir):
    case_dir = init_case(case_dir)
    add_evidence(case_dir, "a.txt", b"hello")
    add_evidence(case_dir, "b.txt", b"world")
    entries = load_entries(case_dir)
    entries.reverse()
    write_log(case_dir, entries)
    log = AuditLog(case_dir)
    ok, message = log.verify(
        public_key=load_public_key(case_dir, key_dir=case_dir / "keys")
    )
    assert ok is False


def test_replace_key_detected(case_dir):
    """A different signing key invalidates existing signatures."""
    case_dir = init_case(case_dir)
    add_evidence(case_dir, "a.txt", b"hello")
    # Generate a brand new keypair and overwrite the public key.
    new_priv, new_pub, _ = generate_keypair(case_dir, key_dir=case_dir / "keys")
    log = AuditLog(case_dir)
    ok, message = log.verify(public_key=new_pub)
    assert ok is False


def test_evidence_tamper_detected(case_dir):
    case_dir = init_case(case_dir)
    ev_path, digest = add_evidence(case_dir, "a.txt", b"hello")
    # Modify the file on disk without updating the log.
    ev_path.write_bytes(b"tampered")
    log = AuditLog(case_dir)
    ok, results = log.verify_evidence(evidence_root=case_dir / "evidence")
    assert ok is False
    assert any(not r["match"] for r in results)


def test_genesis_signature_invalid_detected(case_dir):
    case_dir = init_case(case_dir)
    entries = load_entries(case_dir)
    entries[0]["signature"] = "0" * 128  # bogus signature
    write_log(case_dir, entries)
    log = AuditLog(case_dir)
    ok, message = log.verify(
        public_key=load_public_key(case_dir, key_dir=case_dir / "keys")
    )
    assert ok is False


def test_head_hash_changes_on_append(case_dir):
    case_dir = init_case(case_dir)
    log = AuditLog(case_dir)
    head_before = log.entries[-1]["entry_hash"]
    add_evidence(case_dir, "a.txt", b"hello")
    log = AuditLog(case_dir)
    head_after = log.entries[-1]["entry_hash"]
    assert head_before != head_after
