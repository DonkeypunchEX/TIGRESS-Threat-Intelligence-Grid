"""MITRE ATT&CK technique mapping for TIGRESS detections.

Tags each detection with the ATT&CK technique(s) it evidences, turning TIGRESS
findings into the vocabulary SOCs already speak and enabling coverage
reporting. Mapping is centralized here and applied once, in
``DetectionEngine._deliver``, so rule, ML, correlation, and network detections
are all tagged uniformly.

The primary key is ``features["rule"]`` (the rule id for atomic detections and
the finding name for correlation meta-detections); detection id prefixes cover
the rule-less built-ins. Rules may also declare an ``attack:`` list in
``config/rules.yaml`` to extend the mapping without code changes (passed in as
``overrides``). Techniques that genuinely depend on external context (a raw
Suricata signature, a multi-phase behavioural progression) are left untagged
rather than guessed.
"""

from typing import Any, Dict, Iterable, List, Optional

#: Curated ATT&CK catalog for TIGRESS's detection domains (Enterprise + Mobile).
#: id -> {name, tactic}. Kept small and defensible rather than exhaustive.
TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "T1430": {"name": "Location Tracking", "tactic": "Collection"},
    "T1205.001": {"name": "Port Knocking", "tactic": "Command and Control"},
}

#: ``features["rule"]`` (rule id or correlation finding) -> technique ids.
_RULE_MAP: Dict[str, List[str]] = {
    # WiFi
    "ssid_spoof_suspect": ["T1557"],
    # Bluetooth / BLE physical tracking
    "ble_close_proximity": ["T1430"],
    "ble_tracker_suspect": ["T1430"],
    "ble_tracker_fingerprint": ["T1430"],
    "ble_randomized_mac_close": ["T1430"],
    # Correlation meta-detections
    "entity_persistence": ["T1430"],
    "cross_sensor": ["T1595"],
    "burst": ["T1595"],
    # Network (Suricata / covert channel)
    "covert_channel": ["T1205.001"],
    # Intentionally unmapped (context-dependent): "suricata_alert",
    # "behavioral_progression" — mapping these blindly would be misleading.
}

#: Detection id prefix -> technique ids, for built-ins that carry no rule id.
_ID_PREFIX_MAP: Dict[str, List[str]] = {
    "new_ap_": ["T1595"],
    "new_device_": ["T1595"],
}


def technique(technique_id: str) -> Dict[str, str]:
    """Return the ``{id, name, tactic}`` record for a technique id."""
    meta = TECHNIQUES.get(technique_id)
    if meta is None:
        return {"id": technique_id, "name": technique_id, "tactic": "Unknown"}
    return {"id": technique_id, "name": meta["name"], "tactic": meta["tactic"]}


def resolve(
    detection: Dict[str, Any], overrides: Optional[Dict[str, List[str]]] = None
) -> List[Dict[str, str]]:
    """Return the ATT&CK technique(s) a detection dict evidences.

    ``overrides`` maps a rule id to technique ids (from ``attack:`` declarations
    in ``config/rules.yaml``); its ids are merged with the built-in map as a
    union and then deduplicated — overrides *extend*, they do not replace.
    Returns an empty list when nothing maps — detections are never tagged with a
    guessed technique.
    """
    ids: List[str] = []
    seen = set()

    def _add(tid: str) -> None:
        if tid and tid not in seen:
            seen.add(tid)
            ids.append(tid)

    features = detection.get("features") or {}
    rule = features.get("rule")

    if overrides and rule in overrides:
        for tid in overrides[rule]:
            _add(tid)
    for tid in _RULE_MAP.get(rule, []):
        _add(tid)

    det_id = detection.get("id") or ""
    for prefix, tids in _ID_PREFIX_MAP.items():
        if det_id.startswith(prefix):
            for tid in tids:
                _add(tid)

    return [technique(tid) for tid in ids]


def summarize(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate ATT&CK coverage over detections or persisted event rows.

    Accepts raw detection dicts or event-store rows (which nest the detection
    under ``data``). Returns totals plus per-technique and per-tactic counts,
    newest-agnostic, alongside the technique catalog for reference.
    """
    by_technique: Dict[str, int] = {}
    by_tactic: Dict[str, int] = {}
    names: Dict[str, str] = {}
    tagged = 0
    total = 0
    for record in records:
        total += 1
        payload = record.get("data") if isinstance(record.get("data"), dict) else record
        features = (payload or {}).get("features") or {}
        techniques = features.get("attack") or []
        if techniques:
            tagged += 1
        for tech in techniques:
            tid = tech.get("id")
            if not tid:
                continue
            by_technique[tid] = by_technique.get(tid, 0) + 1
            names[tid] = tech.get("name", tid)
            by_tactic[tech.get("tactic", "Unknown")] = (
                by_tactic.get(tech.get("tactic", "Unknown"), 0) + 1
            )
    techniques_out = [
        {"id": tid, "name": names[tid], "count": by_technique[tid]}
        for tid in sorted(by_technique, key=lambda t: (-by_technique[t], t))
    ]
    return {
        "total_detections": total,
        "attack_tagged": tagged,
        "techniques": techniques_out,
        "by_tactic": dict(sorted(by_tactic.items(), key=lambda kv: (-kv[1], kv[0]))),
    }
