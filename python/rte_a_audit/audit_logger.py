"""Tamper-evident audit logger with hash chain for RTE-A (R3 Observability)."""

import hashlib
import json
import time
from typing import Any, Optional

SCHEMA_VERSION = "1.0"
INITIAL_CHAIN_HASH = "0" * 64


def _canonical_json(obj: dict[str, Any]) -> str:
    """Serialize dict to deterministic JSON (sorted keys)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class AuditLogger:
    """
    Tamper-evident audit logger that chains records via cryptographic hashes.
    Supports R3 (Observability): structured, verifiable evidence for audit.
    """

    def __init__(self, engagement_id: str, operator_id: str) -> None:
        self._engagement_id = engagement_id
        self._operator_id = operator_id
        self._chain_hash = INITIAL_CHAIN_HASH
        self._sequence = 0

    def _hash_result(self, result: Any) -> str:
        """Return truncated SHA-256 hex digest of canonical JSON serialization of result."""
        data = _canonical_json({"result": result})
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]

    def _hash_record(self, record: dict[str, Any]) -> str:
        """Return full SHA-256 hex digest of canonical JSON serialization of record."""
        data = _canonical_json(record)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def log_event(
        self,
        action: str,
        result: Any,
        authorization: str,
        task_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Log an audit event and append to the hash chain.

        Args:
            action: Description of the action performed
            result: Outcome or payload (will be hashed)
            authorization: Reference to approval/task authorization
            task_id: Optional task identifier

        Returns:
            Full record dict including chain_hash and prev_chain_hash
        """
        self._sequence += 1
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        result_hash = self._hash_result(result)
        record: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "engagement_id": self._engagement_id,
            "operator_id": self._operator_id,
            "sequence": self._sequence,
            "timestamp": timestamp,
            "action": action,
            "task_id": task_id,
            "authorization": authorization,
            "result_hash": result_hash,
            "prev_chain_hash": self._chain_hash,
        }

        chain_hash = self._hash_record(record)
        record["chain_hash"] = chain_hash

        self._chain_hash = chain_hash
        return record

    @staticmethod
    def verify_chain(records: list[dict[str, Any]]) -> bool:
        """
        Verify the hash chain integrity across records.

        Args:
            records: List of audit records in order

        Returns:
            True if chain is valid, False if tampering detected
        """
        prev_hash = INITIAL_CHAIN_HASH
        for rec in records:
            if "chain_hash" not in rec or "prev_chain_hash" not in rec:
                return False
            if rec["prev_chain_hash"] != prev_hash:
                return False
            rec_copy = {k: v for k, v in rec.items() if k != "chain_hash"}
            chain_data = _canonical_json(rec_copy)
            expected = hashlib.sha256(chain_data.encode("utf-8")).hexdigest()
            if rec["chain_hash"] != expected:
                return False
            prev_hash = rec["chain_hash"]
        return True
