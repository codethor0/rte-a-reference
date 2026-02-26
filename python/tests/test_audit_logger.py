"""Tests for AuditLogger chain integrity and tamper detection."""

import pytest

from rte_a_audit import AuditLogger


def test_chain_integrity_normal_sequence() -> None:
    """Verify chain integrity for a normal sequence of events."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    records = []
    for i in range(5):
        rec = logger.log_event(
            action=f"action-{i}",
            result={"status": "ok", "seq": i},
            authorization=f"task-{i}",
            task_id=f"task-{i}",
        )
        records.append(rec)
    assert AuditLogger.verify_chain(records) is True


def test_chain_integrity_empty_list() -> None:
    """Empty chain is valid."""
    assert AuditLogger.verify_chain([]) is True


def test_chain_integrity_single_record() -> None:
    """Single record chain is valid."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    rec = logger.log_event(
        action="init",
        result={},
        authorization="approval-001",
    )
    assert AuditLogger.verify_chain([rec]) is True


def test_tamper_detection_modified_record() -> None:
    """Tampering with a record breaks the chain."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    records = []
    for i in range(3):
        rec = logger.log_event(
            action=f"action-{i}",
            result={"seq": i},
            authorization=f"auth-{i}",
        )
        records.append(rec)
    records[1]["action"] = "tampered"
    assert AuditLogger.verify_chain(records) is False


def test_tamper_detection_modified_result_hash() -> None:
    """Changing result_hash breaks chain verification (hash is part of hashed content)."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    rec = logger.log_event(
        action="test",
        result={"x": 1},
        authorization="auth",
    )
    rec["result_hash"] = "0" * 16
    assert AuditLogger.verify_chain([rec]) is False


def test_tamper_detection_removed_record() -> None:
    """Removing a record breaks the chain (prev_chain_hash mismatch)."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    records = []
    for i in range(4):
        rec = logger.log_event(
            action=f"action-{i}",
            result={"seq": i},
            authorization=f"auth-{i}",
        )
        records.append(rec)
    removed = records[:1] + records[2:]
    assert AuditLogger.verify_chain(removed) is False


def test_tamper_detection_reordered_records() -> None:
    """Reordering records breaks the chain."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    r1 = logger.log_event("a1", {"x": 1}, "auth1")
    r2 = logger.log_event("a2", {"x": 2}, "auth2")
    assert AuditLogger.verify_chain([r2, r1]) is False


def test_result_hashing_deterministic() -> None:
    """Result hashing is deterministic for the same payload."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    payload = {"hosts": 5, "open_ports": [22, 443]}
    r1 = logger.log_event("action", payload, "auth")
    logger2 = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    r2 = logger2.log_event("action", payload, "auth")
    assert r1["result_hash"] == r2["result_hash"]


def test_record_structure() -> None:
    """Logged records have expected schema."""
    logger = AuditLogger(engagement_id="eng-001", operator_id="op-alice")
    rec = logger.log_event(
        action="test_action",
        result={"data": "value"},
        authorization="task-123",
        task_id="task-123",
    )
    assert "schema_version" in rec
    assert "engagement_id" in rec
    assert rec["engagement_id"] == "eng-001"
    assert "operator_id" in rec
    assert rec["operator_id"] == "op-alice"
    assert "sequence" in rec
    assert "timestamp" in rec
    assert "action" in rec
    assert rec["action"] == "test_action"
    assert "task_id" in rec
    assert rec["task_id"] == "task-123"
    assert "authorization" in rec
    assert "result_hash" in rec
    assert "prev_chain_hash" in rec
    assert "chain_hash" in rec
