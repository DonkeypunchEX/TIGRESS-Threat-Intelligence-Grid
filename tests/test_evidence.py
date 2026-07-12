import json

import pytest

from src.core.evidence import EvidenceExporter, provenance, sha256_file


def _write_log(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


def test_export_writes_bundle_with_separated_hash(tmp_path):
    log = tmp_path / "forensic.jsonl"
    _write_log(log, [
        {"type": "detection", "data": {"id": "a", "severity": 4, "timestamp": "2026-05-01T00:00:00+00:00"}},
        {"type": "detection", "data": {"id": "b", "severity": 2, "timestamp": "2026-05-02T00:00:00+00:00"}},
    ])
    out = tmp_path / "bundle"
    manifest = EvidenceExporter(str(log)).export(str(out))

    assert manifest["record_count"] == 2
    assert (out / "evidence.jsonl").exists()
    assert (out / "manifest.json").exists()
    assert (out / "CHAIN_OF_CUSTODY.txt").exists()
    assert not (out / "manifest.sig").exists()  # no signer -> unsigned

    # The hash lives in the manifest, separately from evidence.jsonl, and matches.
    assert manifest["sha256"] == sha256_file(out / "evidence.jsonl")
    on_disk = json.loads((out / "manifest.json").read_text())
    assert on_disk["sha256"] == manifest["sha256"]


def test_export_filters_by_time_window_and_type(tmp_path):
    log = tmp_path / "forensic.jsonl"
    _write_log(log, [
        {"type": "detection", "data": {"id": "old", "timestamp": "2026-01-01T00:00:00+00:00"}},
        {"type": "detection", "data": {"id": "mid", "timestamp": "2026-06-01T00:00:00+00:00"}},
        {"type": "boot", "data": {"id": "boot", "timestamp": "2026-06-01T00:00:00+00:00"}},
    ])
    out = tmp_path / "bundle"
    manifest = EvidenceExporter(str(log)).export(
        str(out), since="2026-05-01T00:00:00+00:00", event_types=["detection"],
    )
    assert manifest["record_count"] == 1
    lines = (out / "evidence.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["data"]["id"] == "mid"


def test_export_signs_manifest_when_signer_given(tmp_path):
    pytest.importorskip("cryptography")
    from src.security.audit_log import AuditLog

    log = tmp_path / "forensic.jsonl"
    _write_log(log, [{"type": "detection", "data": {"id": "a"}}])
    out = tmp_path / "bundle"

    signer = AuditLog(log_path=str(tmp_path / "audit"))
    manifest = EvidenceExporter(str(log), signer=signer).export(str(out))
    assert manifest["signed"] is True

    sig = json.loads((out / "manifest.sig").read_text())
    manifest_bytes = (out / "manifest.json").read_bytes()
    assert AuditLog.verify_bytes(manifest_bytes, sig["signature"], sig["public_key"]) is True
    # Any edit to the manifest breaks the signature.
    assert AuditLog.verify_bytes(manifest_bytes + b" ", sig["signature"], sig["public_key"]) is False


def test_export_missing_log_is_empty_bundle(tmp_path):
    out = tmp_path / "bundle"
    manifest = EvidenceExporter(str(tmp_path / "nope.jsonl")).export(str(out))
    assert manifest["record_count"] == 0
    assert (out / "evidence.jsonl").read_text() == ""


def test_provenance_has_tool_version_and_timestamp():
    prov = provenance({"case_id": "CASE-1"})
    assert prov["tool"] == "TIGRESS"
    assert prov["version"]
    assert prov["case_id"] == "CASE-1"
    assert prov["generated_at"].endswith("+00:00")
