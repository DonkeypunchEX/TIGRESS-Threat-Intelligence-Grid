import json

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
