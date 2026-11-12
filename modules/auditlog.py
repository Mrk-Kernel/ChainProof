"""Hash-chained, digitally signed audit log for chain of custody."""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover - Windows lacks fcntl
    _HAS_FCNTL = False

from .signing import load_private_key, load_public_key, sign_data, verify_signature
from .timestamp import TimestampClient

GENESIS_PREV_HASH = "0" * 64
PAYLOAD_FIELDS = ("index", "timestamp", "action", "actor", "evidence", "prev_hash")


class AuditLog:
    def __init__(self, case_dir):
        self.case_dir = Path(case_dir)
        self.log_path = self.case_dir / "logs" / "audit.jsonl"
        self.entries = []
        if self.log_path.exists():
            self._load()

    def _load(self):
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    self.entries.append(json.loads(line))

    def _entry_hash(self, payload):
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _write_entry_locked(self, entry):
        """Append entry with an exclusive file lock and fsync for crash safety."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            try:
                if _HAS_FCNTL:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            except OSError:
                pass  # locking unavailable; append is still atomic for small writes
            fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            try:
                if _HAS_FCNTL:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass

    def genesis(self, actor="system", private_key=None):
        """Create the case initialization (genesis) entry if none exists."""
        if self.entries:
            return self.entries[0]
        payload = {
            "index": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "CASE_INITIALIZED",
            "actor": actor,
            "evidence": None,
            "prev_hash": GENESIS_PREV_HASH,
        }
        entry = {"entry_hash": self._entry_hash(payload), **payload}
        if private_key is not None:
            entry["signature"] = sign_data(
                private_key, entry["entry_hash"].encode("utf-8")
            ).hex()
        else:
            entry["signature"] = ""
        self.entries.append(entry)
        self._write_entry_locked(entry)
        return entry

    def append(self, action, actor, evidence=None, timestamp_token=None, private_key=None):
        """Append a new signed, hash-chained entry to the log."""
        prev_hash = self.entries[-1]["entry_hash"] if self.entries else GENESIS_PREV_HASH
        index = (self.entries[-1]["index"] + 1) if self.entries else 1

        payload = {
            "index": index,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "actor": actor,
            "evidence": evidence,
            "prev_hash": prev_hash,
        }
        entry = {"entry_hash": self._entry_hash(payload), **payload}
        entry["timestamp_token"] = timestamp_token

        if private_key is not None:
            signature = sign_data(private_key, entry["entry_hash"].encode("utf-8"))
            entry["signature"] = signature.hex()
        else:
            entry["signature"] = ""

        self.entries.append(entry)
        self._write_entry_locked(entry)
        return entry

    def verify(self, public_key=None):
        """Verify hash chain integrity and signatures. Returns (ok, message)."""
        if public_key is None:
            public_key = load_public_key(self.case_dir)

        prev = GENESIS_PREV_HASH
        for entry in self.entries:
            payload = {field: entry[field] for field in PAYLOAD_FIELDS}
            expected = self._entry_hash(payload)
            if entry["entry_hash"] != expected:
                return False, f"Entry {entry['index']}: entry hash mismatch"
            if entry["prev_hash"] != prev:
                return False, f"Entry {entry['index']}: hash chain broken"
            try:
                signature = bytes.fromhex(entry["signature"])
            except ValueError:
                return False, f"Entry {entry['index']}: invalid signature encoding"
            if not verify_signature(public_key, entry["entry_hash"].encode("utf-8"), signature):
                return False, f"Entry {entry['index']}: signature invalid"
            prev = entry["entry_hash"]
        return True, f"Verified {len(self.entries)} log entries"

    def verify_evidence(self, evidence_root=None):
        """Re-hash every evidence file referenced in the log and compare.

        Returns (ok, results) where results is a list of dicts with path, logged,
        current, and match fields. Files that no longer exist are reported as missing.
        """
        from .hashing import hash_file

        evidence_root = Path(evidence_root) if evidence_root else self.case_dir / "evidence"
        results = []
        ok = True

        for entry in self.entries:
            evidence = entry.get("evidence") or {}
            if not isinstance(evidence, dict) or "sha256" not in evidence:
                continue
            rel_path = evidence.get("path") or evidence.get("name")
            if not rel_path:
                continue
            # Resolve relative to evidence_root if path is just a name, else as-is.
            candidate = Path(rel_path)
            if not candidate.is_absolute():
                candidate = evidence_root / candidate.name if not candidate.exists() else candidate
                if not candidate.exists():
                    candidate = evidence_root / rel_path
            if not candidate.exists():
                results.append({
                    "path": rel_path,
                    "logged": evidence.get("sha256"),
                    "current": None,
                    "match": False,
                    "error": "missing",
                })
                ok = False
                continue
            try:
                current = hash_file(candidate)
                match = (
                    current["sha256"] == evidence.get("sha256")
                    and current.get("sha3_256") == evidence.get("sha3_256")
                )
                results.append({
                    "path": str(candidate),
                    "logged": evidence.get("sha256"),
                    "current": current["sha256"],
                    "match": match,
                })
                if not match:
                    ok = False
            except Exception as exc:  # noqa: BLE001
                results.append({
                    "path": str(candidate),
                    "logged": evidence.get("sha256"),
                    "current": None,
                    "match": False,
                    "error": str(exc),
                })
                ok = False
        return ok, results

    def anchor_head(self, tsa_url=None, algorithm="sha256"):
        """RFC 3161 timestamp over the current head hash to anchor the chain.

        Returns the timestamp client result dict. Head anchoring makes truncation
        of the last entries detectable only when combined with an externally
        published head hash; by itself it bounds the window of undetectable
        truncation to the interval between anchors.
        """
        if not self.entries:
            return {"status": None, "status_string": "no entries to anchor", "token_b64": None}
        head_hash = self.entries[-1]["entry_hash"]
        client = TimestampClient(tsa_url) if tsa_url else TimestampClient()
        return client.request(head_hash, algorithm=algorithm)
