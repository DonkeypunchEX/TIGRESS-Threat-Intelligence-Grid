import json

from src.core import selftest
from src.version import __version__


def test_run_selftest_passes_on_golden_dataset():
    report = selftest.run_selftest()
    assert report["ok"] is True
    assert report["version"] == __version__
    assert report["dataset_sha256"] == selftest.dataset_hash()
    assert {c["name"] for c in report["checks"]} == {
        "wifi_ssid_spoof", "ble_tracker", "ble_proximity",
    }
    assert all(c["passed"] for c in report["checks"])


def test_run_selftest_writes_versioned_record(tmp_path):
    report = selftest.run_selftest(record_dir=str(tmp_path))
    record_path = tmp_path / report["record_path"].split("/")[-1]
    assert record_path.exists()
    assert __version__ in record_path.name
    on_disk = json.loads(record_path.read_text())
    assert on_disk["ok"] is True


def test_needs_revalidation_true_when_no_record(tmp_path):
    assert selftest.needs_revalidation(str(tmp_path)) is True


def test_needs_revalidation_false_after_passing_current_version(tmp_path):
    selftest.run_selftest(record_dir=str(tmp_path))
    assert selftest.needs_revalidation(str(tmp_path)) is False


def test_needs_revalidation_true_for_stale_version(tmp_path):
    (tmp_path / "validation_0.0.1_20200101T000000Z.json").write_text(
        json.dumps({"ok": True, "version": "0.0.1"})
    )
    assert selftest.needs_revalidation(str(tmp_path)) is True


# --------------------------------------------------------------------------- #
# visibility baseline (Hartong: know your coverage before trusting it)
# --------------------------------------------------------------------------- #

import yaml


def _write_config(tmp_path, enabled, models=None, alerting=None):
    cfg = {
        "sensors": {"enabled": enabled},
        "detection": {"ml_models": models or {}},
        "alerting": alerting if alerting is not None else {"forensic_log": "x.jsonl"},
    }
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return str(path)


def test_visibility_flags_missing_cli(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest.shutil, "which", lambda _c: None)
    report = selftest.visibility_report(_write_config(tmp_path, ["wifi", "bluetooth"]))
    assert report["ok"] is False
    names = {s["name"] for s in report["sensors"]}
    assert names == {"wifi", "bluetooth"}
    assert all(not s["cli_available"] for s in report["sensors"])
    assert any("not on PATH" in w for w in report["warnings"])


def test_visibility_ok_when_all_clis_present(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest.shutil, "which", lambda c: f"/usr/bin/{c}")
    models = {"wifi": str(tmp_path / "m.pkl")}
    (tmp_path / "m.pkl").write_text("trained")
    report = selftest.visibility_report(_write_config(tmp_path, ["wifi"], models=models))
    assert report["ok"] is True
    wifi = report["sensors"][0]
    assert wifi["cli_available"] is True
    assert wifi["model_trained"] is True
    assert report["warnings"] == []


def test_visibility_warns_on_untrained_model(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest.shutil, "which", lambda c: f"/usr/bin/{c}")
    models = {"wifi": str(tmp_path / "missing.pkl")}  # file absent = untrained
    report = selftest.visibility_report(_write_config(tmp_path, ["wifi"], models=models))
    assert report["ok"] is True  # untrained model is a warning, not blindness
    assert any("not trained" in w for w in report["warnings"])


def test_visibility_warns_when_no_log_sink(tmp_path, monkeypatch):
    monkeypatch.setattr(selftest.shutil, "which", lambda c: f"/usr/bin/{c}")
    report = selftest.visibility_report(
        _write_config(tmp_path, ["wifi"], alerting={})
    )
    assert any("not persisted" in w for w in report["warnings"])
    assert report["log_sources"] == {"forensic_log": False, "event_db": False}
