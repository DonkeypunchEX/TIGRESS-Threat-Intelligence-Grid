from src.core import attack


def test_resolve_maps_known_rules():
    assert [t["id"] for t in attack.resolve({"features": {"rule": "ssid_spoof_suspect"}})] == ["T1557"]
    assert [t["id"] for t in attack.resolve({"features": {"rule": "ble_tracker_suspect"}})] == ["T1430"]
    assert [t["id"] for t in attack.resolve({"features": {"rule": "covert_channel"}})] == ["T1205.001"]


def test_resolve_maps_correlation_findings():
    assert [t["id"] for t in attack.resolve({"features": {"rule": "entity_persistence"}})] == ["T1430"]
    assert [t["id"] for t in attack.resolve({"features": {"rule": "burst"}})] == ["T1595"]


def test_resolve_maps_id_prefix_for_ruleless_builtins():
    techs = attack.resolve({"id": "new_ap_abc123", "features": {}})
    assert [t["id"] for t in techs] == ["T1595"]


def test_resolve_returns_empty_for_unmapped():
    assert attack.resolve({"features": {"rule": "suricata_alert"}}) == []
    assert attack.resolve({"id": "ml_deadbeef", "features": {}}) == []
    assert attack.resolve({}) == []


def test_resolve_overrides_take_precedence_and_extend():
    techs = attack.resolve(
        {"features": {"rule": "my_custom_rule"}}, overrides={"my_custom_rule": ["T1595"]}
    )
    assert [t["id"] for t in techs] == ["T1595"]


def test_resolve_dedupes():
    techs = attack.resolve(
        {"features": {"rule": "ssid_spoof_suspect"}}, overrides={"ssid_spoof_suspect": ["T1557"]}
    )
    assert [t["id"] for t in techs] == ["T1557"]  # not duplicated


def test_technique_lookup_and_unknown():
    t = attack.technique("T1430")
    assert t == {"id": "T1430", "name": "Location Tracking", "tactic": "Collection"}
    assert attack.technique("T9999")["tactic"] == "Unknown"


def test_summarize_tallies_techniques_and_tactics():
    records = [
        {"data": {"features": {"attack": [{"id": "T1430", "name": "Location Tracking", "tactic": "Collection"}]}}},
        {"data": {"features": {"attack": [{"id": "T1430", "name": "Location Tracking", "tactic": "Collection"}]}}},
        {"data": {"features": {"attack": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}]}}},
        {"data": {"features": {}}},  # untagged
    ]
    summary = attack.summarize(records)
    assert summary["total_detections"] == 4
    assert summary["attack_tagged"] == 3
    assert summary["techniques"][0] == {"id": "T1430", "name": "Location Tracking", "count": 2}
    assert summary["by_tactic"] == {"Collection": 2, "Credential Access": 1}


def test_summarize_accepts_raw_detection_dicts():
    records = [{"features": {"attack": [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}]}}]
    summary = attack.summarize(records)
    assert summary["attack_tagged"] == 1
    assert summary["by_tactic"] == {"Reconnaissance": 1}
