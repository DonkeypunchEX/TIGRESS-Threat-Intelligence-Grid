import json
import time

from src.utils.forensic_logger import ForensicLogger


def test_writes_jsonl_entries(tmp_path):
    log_path = tmp_path / "nested" / "forensic.jsonl"
    logger = ForensicLogger(str(log_path))
    logger.log("detection", {"id": "abc", "severity": 4})
    logger.log("detection", {"id": "def", "severity": 2})

    lines = log_path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["type"] == "detection"
    assert first["data"]["id"] == "abc"


def test_rotation_writes_dated_file_and_hash_sidecar(tmp_path):
    log_path = tmp_path / "forensic.jsonl"
    logger = ForensicLogger(str(log_path), max_bytes=120)
    for i in range(6):
        logger.log("detection", {"id": f"d{i}", "severity": 3})

    rotated = list(tmp_path.glob("forensic_*.jsonl"))
    assert rotated, "expected at least one rotated file"
    sidecar = rotated[0].with_suffix(rotated[0].suffix + ".sha256")
    assert sidecar.exists()
    meta = json.loads(sidecar.read_text())
    assert meta["algorithm"] == "SHA-256"
    # The sidecar hash matches the rotated file's actual content.
    import hashlib
    assert meta["sha256"] == hashlib.sha256(rotated[0].read_bytes()).hexdigest()


def test_rotation_signs_sidecar_when_signer_given(tmp_path):
    import pytest
    pytest.importorskip("cryptography")
    from src.security.audit_log import AuditLog

    signer = AuditLog(log_path=str(tmp_path / "audit"))
    log_path = tmp_path / "forensic.jsonl"
    logger = ForensicLogger(str(log_path), max_bytes=80, signer=signer)
    for i in range(5):
        logger.log("detection", {"id": f"d{i}"})

    sidecar = next(tmp_path.glob("forensic_*.jsonl.sha256"))
    meta = json.loads(sidecar.read_text())
    assert AuditLog.verify_bytes(
        meta["sha256"].encode(), meta["signature"], meta["public_key"]
    ) is True


def test_retention_prunes_old_rotated_files(tmp_path):
    log_path = tmp_path / "forensic.jsonl"
    logger = ForensicLogger(str(log_path), max_bytes=80, retention_days=1)

    # Fabricate an old rotated file and age it beyond the retention window.
    old = tmp_path / "forensic_20000101_000000.jsonl"
    old.write_text('{"type": "detection", "data": {}}\n')
    old_time = time.time() - 3 * 86400
    import os
    os.utime(old, (old_time, old_time))

    for i in range(5):  # trigger a rotation, which prunes
        logger.log("detection", {"id": f"d{i}"})

    assert not old.exists()  # pruned by retention
