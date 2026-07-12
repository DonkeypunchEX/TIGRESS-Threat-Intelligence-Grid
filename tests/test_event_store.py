from src.core.event_store import EventStore, NullEventStore


def _seed(store):
    store.record("detection", {
        "id": "a", "severity": 4, "sensor_type": "wifi",
        "description": "rogue AP", "timestamp": "2026-05-01T00:00:00+00:00",
    })
    store.record("detection", {
        "id": "b", "severity": 2, "sensor_type": "bluetooth",
        "description": "new device", "timestamp": "2026-05-02T00:00:00+00:00",
    })
    store.record("tamper", {
        "severity": 5, "description": "file changed",
        "timestamp": "2026-05-02T12:00:00+00:00",
    })


def test_record_and_recent_newest_first(tmp_path):
    store = EventStore(str(tmp_path / "events.db"))
    _seed(store)
    rows = store.recent()
    assert [r["type"] for r in rows] == ["tamper", "detection", "detection"]
    assert rows[0]["data"]["description"] == "file changed"  # JSON round-trips


def test_recent_filters(tmp_path):
    store = EventStore(str(tmp_path / "events.db"))
    _seed(store)
    assert len(store.recent(event_type="detection")) == 2
    assert len(store.recent(min_severity=4)) == 2  # sev 4 and 5
    assert len(store.recent(sensor_type="wifi")) == 1
    assert len(store.recent(since="2026-05-02T00:00:00+00:00")) == 2
    assert len(store.recent(until="2026-05-01T23:59:59+00:00")) == 1
    assert len(store.recent(text="rogue")) == 1


def test_recent_limit(tmp_path):
    store = EventStore(str(tmp_path / "events.db"))
    _seed(store)
    assert len(store.recent(limit=1)) == 1


def test_summary_counts(tmp_path):
    store = EventStore(str(tmp_path / "events.db"))
    _seed(store)
    s = store.summary()
    assert s["total"] == 3
    assert s["by_type"] == {"detection": 2, "tamper": 1}
    assert s["by_severity"] == {"2": 1, "4": 1, "5": 1}
    assert s["by_sensor_type"] == {"wifi": 1, "bluetooth": 1}


def test_analytics_buckets_and_top(tmp_path):
    store = EventStore(str(tmp_path / "events.db"))
    _seed(store)
    a = store.analytics(bucket="day", event_type="detection")
    assert a["counts"] == [
        {"bucket": "2026-05-01", "count": 1},
        {"bucket": "2026-05-02", "count": 1},
    ]
    # Only detection descriptions, most frequent first.
    descs = {t["description"] for t in a["top_descriptions"]}
    assert descs == {"rogue AP", "new device"}


def test_add_detection_helper(tmp_path):
    store = EventStore(str(tmp_path / "events.db"))
    store.add_detection({"id": "x", "severity": 3, "sensor_type": "phone", "description": "d"})
    row = store.recent()[0]
    assert row["type"] == "detection"
    assert row["severity"] == 3


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "events.db"
    store = EventStore(str(path))
    _seed(store)
    assert store.count() == 3
    store.close()

    reopened = EventStore(str(path))
    assert reopened.count() == 3  # survived the restart
    assert len(reopened.recent(event_type="detection")) == 2


def test_recent_caps_limit(tmp_path, monkeypatch):
    import src.core.event_store as es
    monkeypatch.setattr(es, "MAX_LIMIT", 2)
    store = es.EventStore(str(tmp_path / "events.db"))
    for i in range(4):
        store.record("detection", {"id": str(i), "severity": 1})
    assert len(store.recent(limit=10_000_000)) == 2  # bounded, not 4


def test_null_store_is_inert():
    store = NullEventStore()
    store.record("detection", {"severity": 4})
    store.add_detection({"severity": 4})
    assert store.recent() == []
    assert store.count() == 0
    assert store.summary()["total"] == 0
    assert store.analytics()["counts"] == []
    assert store.enabled is False
