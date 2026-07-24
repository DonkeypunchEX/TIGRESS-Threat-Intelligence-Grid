from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from src.core.detection_store import DetectionStore
from src.core.event_store import EventStore
from src.dashboard import app


@pytest.fixture
def manager_with_detections(monkeypatch):
    store = DetectionStore()
    store.add({"id": "a", "severity": 2, "sensor_type": "wifi"})
    store.add({"id": "b", "severity": 5, "sensor_type": "wifi"})
    store.add({"id": "c", "severity": 5, "sensor_type": "phone"})
    fake = SimpleNamespace(detection_engine=SimpleNamespace(history=store))
    monkeypatch.setattr(app, "_manager", fake)
    return store


@pytest.fixture
def manager_with_events(monkeypatch, tmp_path):
    events = EventStore(str(tmp_path / "events.db"))
    events.record("detection", {"id": "a", "severity": 2, "sensor_type": "wifi",
                                "description": "low", "timestamp": "2026-05-01T00:00:00+00:00"})
    events.record("detection", {"id": "b", "severity": 5, "sensor_type": "wifi",
                                "description": "high", "timestamp": "2026-05-02T00:00:00+00:00"})
    events.record("tamper", {"severity": 5, "description": "file changed",
                             "timestamp": "2026-05-02T00:00:00+00:00"})
    fake = SimpleNamespace(detection_engine=SimpleNamespace(event_store=events))
    monkeypatch.setattr(app, "_manager", fake)
    return events


def test_detections_endpoint_newest_first(manager_with_detections):
    result = app.detections()
    assert [d["id"] for d in result] == ["c", "b", "a"]


def test_detections_endpoint_filters(manager_with_detections):
    high_wifi = app.detections(min_severity=4, sensor_type="wifi")
    assert [d["id"] for d in high_wifi] == ["b"]

    limited = app.detections(limit=1)
    assert [d["id"] for d in limited] == ["c"]


def test_detections_summary_endpoint(manager_with_detections):
    summary = app.detections_summary()
    assert summary["total"] == 3
    assert summary["by_severity"] == {"2": 1, "5": 2}
    assert summary["by_sensor_type"] == {"wifi": 2, "phone": 1}


def test_events_endpoint_filters_and_persists(manager_with_events):
    assert [e["type"] for e in app.events()] == ["tamper", "detection", "detection"]
    assert [e["data"]["id"] for e in app.events(event_type="detection")] == ["b", "a"]
    assert len(app.events(min_severity=5)) == 2
    assert [e["data"]["id"] for e in app.events(q="high")] == ["b"]
    assert len(app.events(since="2026-05-02T00:00:00+00:00")) == 2


def test_events_summary_endpoint(manager_with_events):
    summary = app.events_summary()
    assert summary["total"] == 3
    assert summary["by_type"] == {"detection": 2, "tamper": 1}


def test_analytics_endpoint(manager_with_events):
    a = app.analytics(bucket="day", event_type="detection")
    assert a["counts"] == [
        {"bucket": "2026-05-01", "count": 1},
        {"bucket": "2026-05-02", "count": 1},
    ]
    assert {t["description"] for t in a["top_descriptions"]} == {"low", "high"}


def test_attack_coverage_endpoint(manager_with_events, monkeypatch):
    events = manager_with_events
    events.record("detection", {"id": "t1", "severity": 4, "sensor_type": "bluetooth",
                                "features": {"attack": [
                                    {"id": "T1430", "name": "Location Tracking",
                                     "tactic": "Collection"}]}})
    events.record("detection", {"id": "t2", "severity": 4, "sensor_type": "bluetooth",
                                "features": {"attack": [
                                    {"id": "T1430", "name": "Location Tracking",
                                     "tactic": "Collection"}]}})
    # event_store fixture manager lacks .history; enable flag already True.
    cov = app.attack_coverage()
    assert cov["attack_tagged"] == 2
    assert cov["techniques"][0] == {"id": "T1430", "name": "Location Tracking", "count": 2}
    assert cov["by_tactic"] == {"Collection": 2}
    assert "T1430" in cov["catalog"]


def test_attack_coverage_counts_full_population_past_cap(manager_with_events):
    events = manager_with_events
    tag = [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}]
    for i in range(1500):  # more than MAX_LIMIT
        events.record("detection", {"id": f"n{i}", "severity": 3, "features": {"attack": tag}})
    cov = app.attack_coverage()
    # All 1500 tagged detections counted, not truncated at MAX_LIMIT.
    assert cov["techniques"][0] == {"id": "T1595", "name": "Active Scanning", "count": 1500}


def test_attack_coverage_history_fallback_respects_window(monkeypatch):
    store = DetectionStore()
    tag = [{"id": "T1430", "name": "Location Tracking", "tactic": "Collection"}]
    store.add({"id": "old", "severity": 4, "features": {"attack": tag},
               "timestamp": "2026-01-01T00:00:00+00:00"})
    store.add({"id": "new", "severity": 4, "features": {"attack": tag},
               "timestamp": "2026-06-01T00:00:00+00:00"})
    # event_store disabled -> falls back to in-memory history.
    engine = SimpleNamespace(event_store=SimpleNamespace(enabled=False), history=store)
    monkeypatch.setattr(app, "_manager", SimpleNamespace(detection_engine=engine))

    cov = app.attack_coverage(since="2026-05-01T00:00:00+00:00")
    assert cov["attack_tagged"] == 1  # only the in-window "new" detection


def test_endpoints_safe_without_manager(monkeypatch):
    monkeypatch.setattr(app, "_manager", None)
    assert app.detections() == []
    assert app.detections_summary()["total"] == 0
    assert app.events() == []
    assert app.events_summary()["total"] == 0
    assert app.analytics()["counts"] == []
    cov = app.attack_coverage()
    assert cov["attack_tagged"] == 0
    assert "catalog" in cov  # schema stays consistent without a manager


def test_detections_pyramid_level_filter(monkeypatch):
    store = DetectionStore()
    store.add({"id": "a", "severity": 3, "sensor_type": "wifi",
               "features": {"pyramid_level": "address"}})
    store.add({"id": "b", "severity": 4, "sensor_type": "correlation",
               "features": {"pyramid_level": "ttp"}})
    fake = SimpleNamespace(detection_engine=SimpleNamespace(history=store))
    monkeypatch.setattr(app, "_manager", fake)

    assert [d["id"] for d in app.detections(pyramid_level="ttp")] == ["b"]
    assert [d["id"] for d in app.detections(pyramid_level="address")] == ["a"]
    summary = app.detections_summary()
    assert summary["by_pyramid_level"] == {"address": 1, "ttp": 1}


def test_strict_token_dependency_refuses_when_unconfigured(monkeypatch):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(app, "_api_token", None)
    with pytest.raises(HTTPException) as exc:
        app._require_token_strict(authorization=None)
    assert exc.value.status_code == 403

    monkeypatch.setattr(app, "_api_token", "s3cr3t")
    app._require_token_strict(authorization="Bearer s3cr3t")  # must not raise
    with pytest.raises(HTTPException) as exc:
        app._require_token_strict(authorization="Bearer nope")
    assert exc.value.status_code == 401
