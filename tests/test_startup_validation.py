import logging

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from src.core.selftest import run_selftest
from src.dashboard import app as appmod
from src.dashboard.app import _enforce_validation


def test_warns_when_no_validation_record(tmp_path, caplog):
    config = {"app": {"validation_dir": str(tmp_path)}}
    with caplog.at_level(logging.WARNING):
        _enforce_validation(config, secure=False)  # non-secure: warn only
    assert any("self-validation" in r.message for r in caplog.records)


def test_no_warning_after_passing_validation(tmp_path, caplog):
    run_selftest(record_dir=str(tmp_path))  # records a passing validation
    config = {"app": {"validation_dir": str(tmp_path)}}
    with caplog.at_level(logging.WARNING):
        _enforce_validation(config, secure=False)
    assert not any("self-validation" in r.message for r in caplog.records)


def test_secure_validates_and_continues_when_selftest_passes(tmp_path):
    config = {"app": {"validation_dir": str(tmp_path)}}
    # No record yet -> under --secure the self-test runs inline; the golden
    # dataset passes, so startup must NOT be refused and a record is written.
    _enforce_validation(config, secure=True)
    assert list(tmp_path.glob("validation_*.json"))  # record written


def test_secure_refuses_to_start_when_selftest_fails(tmp_path, monkeypatch):
    config = {"app": {"validation_dir": str(tmp_path)}}
    monkeypatch.setattr(appmod, "_manager", None, raising=False)
    monkeypatch.setattr(
        "src.core.selftest.run_selftest",
        lambda record_dir=None: {"ok": False, "checks": [{"name": "wifi_ssid_spoof", "passed": False}]},
    )
    with pytest.raises(SystemExit, match="self-validation failed"):
        _enforce_validation(config, secure=True)


def test_secure_skips_validation_when_already_current(tmp_path, monkeypatch):
    run_selftest(record_dir=str(tmp_path))  # a passing current-version record exists
    calls = []
    monkeypatch.setattr(
        "src.core.selftest.run_selftest",
        lambda record_dir=None: calls.append(record_dir) or {"ok": True, "checks": []},
    )
    _enforce_validation({"app": {"validation_dir": str(tmp_path)}}, secure=True)
    assert not calls  # needs_revalidation was False, so no re-run
