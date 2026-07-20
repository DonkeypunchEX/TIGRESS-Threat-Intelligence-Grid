from src.core.correlation_engine import CorrelationEngine
from src.core.network_ingest import eve_to_detection, eve_to_detections


def _eve(severity=1, dest_ip="203.0.113.9", signature="ET MALWARE C2 Beacon"):
    return {
        "timestamp": "2026-07-17T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "dest_ip": dest_ip,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": signature,
            "signature_id": 2027863,
            "category": "Malware Command and Control Activity Detected",
            "severity": severity,
        },
    }


# --------------------------------------------------------------------------- #
# EVE mapping
# --------------------------------------------------------------------------- #

def test_alert_maps_to_network_detection():
    det = eve_to_detection(_eve())
    assert det["sensor_type"] == "network"
    assert det["sensor_id"] == "suricata"
    assert det["severity"] == 5  # suricata severity 1 = most severe
    assert det["description"] == "ET MALWARE C2 Beacon"
    assert det["features"]["dest_ip"] == "203.0.113.9"
    assert det["features"]["signature_id"] == 2027863


def test_severity_mapping_bands():
    assert eve_to_detection(_eve(severity=1))["severity"] == 5
    assert eve_to_detection(_eve(severity=2))["severity"] == 4
    assert eve_to_detection(_eve(severity=3))["severity"] == 3
    assert eve_to_detection(_eve(severity=99))["severity"] == 2


def test_non_alert_records_rejected():
    assert eve_to_detection({"event_type": "flow", "src_ip": "1.2.3.4"}) is None
    assert eve_to_detection({"event_type": "dns"}) is None
    assert eve_to_detection("not a dict") is None
    dets, rejected = eve_to_detections([_eve(), {"event_type": "stats"}, None])
    assert len(dets) == 1
    assert rejected == 2


def test_single_record_payload_accepted():
    dets, rejected = eve_to_detections(_eve())
    assert len(dets) == 1
    assert rejected == 0


# --------------------------------------------------------------------------- #
# engine + correlation integration
# --------------------------------------------------------------------------- #

def test_engine_ingest_dispatches_to_history(engine):
    result = engine.ingest_network([_eve(), {"event_type": "flow"}])
    assert result == {"accepted": 1, "rejected": 1}
    recorded = engine.history.recent(sensor_type="network")
    assert len(recorded) == 1
    assert recorded[0]["features"]["pyramid_level"] == "artifact"  # has signature


def test_recurring_dest_ip_trips_persistence():
    eng = CorrelationEngine({
        "enabled": True,
        "window_seconds": 600,
        "cooldown_seconds": 300,
        "rules": {
            "entity_persistence": {"enabled": True, "min_hits": 3, "min_span_seconds": 60},
            "cross_sensor": {"enabled": False},
            "burst": {"enabled": False},
        },
    })
    det = eve_to_detection(_eve(dest_ip="203.0.113.9"))
    eng.observe([det], now=0)
    eng.observe([det], now=100)
    meta = eng.observe([det], now=200)
    assert len(meta) == 1
    assert meta[0]["features"]["entity"] == "ip:203.0.113.9"


def test_src_ip_is_not_an_entity():
    # The source (the user's own device/router) recurs in every alert and
    # must never look like a persisting threat entity.
    eng = CorrelationEngine({
        "enabled": True,
        "rules": {
            "entity_persistence": {"enabled": True, "min_hits": 2, "min_span_seconds": 10},
            "cross_sensor": {"enabled": False},
            "burst": {"enabled": False},
        },
    })
    for t, ip in ((0, "203.0.113.1"), (100, "203.0.113.2"), (200, "203.0.113.3")):
        meta = eng.observe([eve_to_detection(_eve(dest_ip=ip))], now=t)
        assert meta == []  # same src_ip throughout, distinct dest_ips


def test_allowlisted_dest_ip_excluded():
    eng = CorrelationEngine({
        "enabled": True,
        "allowlist": {"entities": ["ip:203.0.113.9"]},
        "rules": {
            "entity_persistence": {"enabled": True, "min_hits": 2, "min_span_seconds": 10},
            "cross_sensor": {"enabled": False},
            "burst": {"enabled": False},
        },
    })
    det = eve_to_detection(_eve(dest_ip="203.0.113.9"))
    eng.observe([det], now=0)
    assert eng.observe([det], now=100) == []


# --------------------------------------------------------------------------- #
# covert channel: Bvp47 "SYN knock" detection
# --------------------------------------------------------------------------- #

from src.core.network_ingest import covert_channel_detection, covert_channel_tag


def _syn_knock(payload_len=264, tcp_flags="02", with_alert=False):
    event = {
        "timestamp": "2026-07-17T12:00:00.000000+0000",
        "src_ip": "198.51.100.7",
        "dest_ip": "192.168.1.50",
        "dest_port": 80,
        "proto": "TCP",
        "tcp": {"tcp_flags": tcp_flags},
        "payload_len": payload_len,
    }
    if with_alert:
        event["event_type"] = "alert"
        event["alert"] = {"signature": "ET SCAN suspicious", "severity": 2}
    return event


def test_syn_with_payload_is_covert_channel():
    assert covert_channel_tag(_syn_knock()) == "syn_payload"


def test_plain_syn_without_payload_is_not_flagged():
    assert covert_channel_tag(_syn_knock(payload_len=0)) is None


def test_syn_ack_with_payload_is_not_a_knock():
    # 0x12 = SYN+ACK: a normal handshake response, not a knock.
    assert covert_channel_tag(_syn_knock(tcp_flags="12")) is None


def test_syn_flags_via_booleans():
    event = {"tcp": {"syn": True, "ack": False}, "payload_len": 100}
    assert covert_channel_tag(event) == "syn_payload"


def test_covert_channel_detection_is_ttp_band():
    det = covert_channel_detection(_syn_knock())
    assert det["sensor_type"] == "network"
    assert det["features"]["pyramid_level"] == "ttp"
    assert det["features"]["covert_channel"] == "syn_payload"
    assert det["phase"] == "covert_channel"
    assert det["severity"] == 4


def test_non_alert_syn_knock_is_synthesized_not_rejected():
    # No IDS alert object, but a SYN knock: must still become a detection.
    dets, rejected = eve_to_detections(_syn_knock())
    assert rejected == 0
    assert len(dets) == 1
    assert dets[0]["features"]["covert_channel"] == "syn_payload"


def test_alert_that_is_also_syn_knock_is_escalated():
    det = eve_to_detection(_syn_knock(with_alert=True))
    assert det["features"]["covert_channel"] == "syn_payload"
    assert det["features"]["pyramid_level"] == "ttp"
    assert det["severity"] == 4  # max(alert severity 4, floor 4)


def test_ordinary_flow_record_still_rejected():
    dets, rejected = eve_to_detections({"event_type": "flow", "tcp": {"tcp_flags": "18"}})
    assert dets == []
    assert rejected == 1
