from src.core.correlation_engine import CorrelationEngine


def _det(address="de:ad:be:ef:00:01", phase=None, weight=0.0, sensor_type="bluetooth"):
    return {
        "id": "d1",
        "sensor_type": sensor_type,
        "confidence": 0.8,
        "severity": 3,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "sensor_id": f"{sensor_type}_sensor",
        "description": "test",
        "features": {"address": address},
        "phase": phase,
        "weight": weight,
    }


def _engine(**rules):
    base = {
        "entity_persistence": {"enabled": False},
        "cross_sensor": {"enabled": False},
        "burst": {"enabled": False},
        "behavioral_progression": {"enabled": False},
        "ibad_outliers": {"enabled": False},
    }
    base.update(rules)
    return CorrelationEngine({
        "enabled": True, "window_seconds": 600, "cooldown_seconds": 300, "rules": base,
    })


# --------------------------------------------------------------------------- #
# behavioural progression
# --------------------------------------------------------------------------- #

def test_progression_fires_across_distinct_phases():
    eng = _engine(behavioral_progression={
        "enabled": True, "min_phases": 2, "min_weight": 4, "severity": 5,
    })
    eng.observe([_det(phase="tracking", weight=3)], now=0)
    meta = eng.observe([_det(phase="evasion", weight=3)], now=10)
    prog = [m for m in meta if m["features"]["rule"] == "behavioral_progression"]
    assert len(prog) == 1
    assert prog[0]["severity"] == 5
    assert prog[0]["features"]["phase_count"] == 2
    assert sorted(prog[0]["features"]["phases"]) == ["evasion", "tracking"]


def test_progression_needs_multiple_phases_not_just_weight():
    eng = _engine(behavioral_progression={
        "enabled": True, "min_phases": 2, "min_weight": 4,
    })
    # Lots of weight, but all in a single phase → not progression.
    eng.observe([_det(phase="tracking", weight=5)], now=0)
    meta = eng.observe([_det(phase="tracking", weight=5)], now=10)
    assert [m for m in meta if m["features"]["rule"] == "behavioral_progression"] == []


def test_progression_ignores_unscored_detections():
    eng = _engine(behavioral_progression={"enabled": True, "min_phases": 2, "min_weight": 1})
    # No phase/weight metadata at all → no progression.
    for t in (0, 10, 20):
        meta = eng.observe([_det()], now=t)
    assert [m for m in meta if m["features"]["rule"] == "behavioral_progression"] == []


# --------------------------------------------------------------------------- #
# I-BAD Isolation Forest outliers
# --------------------------------------------------------------------------- #

def test_ibad_flags_outlier_entity():
    eng = _engine(ibad_outliers={
        "enabled": True, "min_entities": 5, "contamination": 0.15, "severity": 5,
    })
    # Five quiet entities (1 detection each) and one loud outlier (many hits,
    # high weight) in the same window.
    batch = [_det(address=f"aa:bb:cc:00:00:0{i}", weight=1) for i in range(5)]
    for _ in range(6):
        batch.append(_det(address="de:ad:be:ef:ff:ff", phase="tracking", weight=5))
    meta = eng.observe(batch, now=0)
    ibad = [m for m in meta if m["features"]["rule"] == "ibad_outliers"]
    assert ibad, "expected an I-BAD outlier meta-detection"
    assert any(m["features"]["entity"] == "bt:de:ad:be:ef:ff:ff" for m in ibad)


def test_ibad_skips_below_min_entities():
    eng = _engine(ibad_outliers={"enabled": True, "min_entities": 5})
    meta = eng.observe([_det(address="aa:bb", weight=5)], now=0)
    assert [m for m in meta if m["features"]["rule"] == "ibad_outliers"] == []


def test_ibad_skips_when_no_variance():
    eng = _engine(ibad_outliers={"enabled": True, "min_entities": 3})
    # Identical score vectors → Isolation Forest has nothing to separate.
    batch = [_det(address=f"aa:bb:cc:00:00:0{i}", weight=1) for i in range(5)]
    meta = eng.observe(batch, now=0)
    assert [m for m in meta if m["features"]["rule"] == "ibad_outliers"] == []
