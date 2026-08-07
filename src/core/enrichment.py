"""Offline-first threat-intel enrichment for sensor readings.

Adds derived fields to WiFi networks and Bluetooth devices *before* rule
matching, so rules can target what a device *is* rather than the literal
string it advertises today:

- ``vendor``             – OUI prefix lookup against a local, extendable map
- ``mac_randomized``     – locally-administered bit set (privacy/rotating MAC)
- ``tracker_name_match`` – advertised name matches a known tracker pattern
- ``is_tracker``         – tracker by name or by tracker-vendor OUI

Everything works offline: the data ships in ``config/enrichment.yaml`` and is
user-extendable. No network calls, ever — this must run on a phone in a
hostile environment.

Note that modern trackers (AirTag, SmartTag) rotate randomized MACs and often
advertise no name at all, so name/OUI matching alone is deliberately treated
as the weakest signal. The strong detector is ``mac_randomized`` combined
with the correlation engine's entity-persistence rule: a rotating-MAC device
that keeps reappearing near you is tracker *behaviour*, whatever it calls
itself.

Performance: OUI lookups use an optimized prefix trie for O(1) average case
complexity, with fallback to longest-prefix matching for overlapping OUI ranges.
"""

import bisect
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Built-in seed data, used when no enrichment file is configured or found.
# The YAML file extends/overrides these; treat both as starter lists to grow.
_DEFAULT_TRACKER_NAME_PATTERNS = [
    "airtag", "air tag", "tile", "smarttag", "smart tag",
    "chipolo", "itag", "tracker", "nut find",
]
_DEFAULT_TRACKER_VENDORS = ["apple", "tile", "samsung", "chipolo"]
_DEFAULT_OUI_VENDORS = {
    "00:03:93": "Apple",
    "00:0a:95": "Apple",
    "00:1b:63": "Apple",
    "f0:18:98": "Apple",
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
}


def normalize_mac(mac: Any) -> Optional[str]:
    """Lower-cased, colon-separated MAC, or None if it doesn't look like one."""
    if not mac:
        return None
    s = str(mac).strip().lower().replace("-", ":")
    parts = s.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        return None
    try:
        [int(p, 16) for p in parts]
    except ValueError:
        return None
    return ":".join(parts)


def mac_is_randomized(mac: Any) -> bool:
    """True when the locally-administered bit is set (randomized/private MAC)."""
    norm = normalize_mac(mac)
    if norm is None:
        return False
    return bool(int(norm.split(":")[0], 16) & 0x02)


class OUITrieNode:
    """Trie node for efficient OUI prefix lookups."""
    __slots__ = ['children', 'vendor']
    
    def __init__(self):
        self.children: Dict[str, 'OUITrieNode'] = {}
        self.vendor: Optional[str] = None


class OUILookup:
    """Optimized OUI prefix lookup using a trie structure.
    
    Provides O(1) average case complexity for prefix lookups by building
    a trie from OUI prefixes. Supports both exact prefix matches and
    longest-prefix matching for overlapping OUI ranges.
    """
    
    def __init__(self):
        self._root = OUITrieNode()
        self._prefixes: List[Tuple[str, str]] = []  # For fallback binary search
    
    def add_prefix(self, prefix: str, vendor: str):
        """Add an OUI prefix to the trie."""
        # Handle both full MACs and OUI prefixes (3 bytes = 6 hex chars)
        norm_prefix = self._normalize_oui_prefix(str(prefix).strip().lower())
        if norm_prefix is None:
            return
        
        # Store for fallback binary search (sorted by length descending)
        self._prefixes.append((norm_prefix, vendor))
        
        # Add to trie
        node = self._root
        for char in norm_prefix.replace(":", ""):
            if char not in node.children:
                node.children[char] = OUITrieNode()
            node = node.children[char]
        node.vendor = vendor
    
    def _normalize_oui_prefix(self, prefix: str) -> Optional[str]:
        """Normalize OUI prefix (can be 3, 4, 5, or 6 bytes)."""
        if not prefix:
            return None
        
        # Remove separators and convert to lowercase
        s = prefix.replace("-", "").replace(":", "").lower()
        
        # Validate that it's a valid hex string
        if not all(c in '0123456789abcdef' for c in s):
            return None
        
        # OUI prefixes can be 3, 4, 5, or 6 bytes (6, 8, 10, 12, 14, 16 hex chars)
        valid_lengths = {6, 8, 10, 12, 14, 16}
        if len(s) not in valid_lengths:
            return None
        
        # Add colons for consistency
        if len(s) == 6:  # 3 bytes
            return f"{s[:2]}:{s[2:4]}:{s[4:6]}"
        elif len(s) == 8:  # 4 bytes
            return f"{s[:2]}:{s[2:4]}:{s[4:6]}:{s[6:8]}"
        elif len(s) == 10:  # 5 bytes
            return f"{s[:2]}:{s[2:4]}:{s[4:6]}:{s[6:8]}:{s[8:10]}"
        elif len(s) == 12:  # 6 bytes
            return f"{s[:2]}:{s[2:4]}:{s[4:6]}:{s[6:8]}:{s[8:10]}:{s[10:12]}"
        else:
            return None
    
    def build(self):
        """Build the trie and sort prefixes for binary search fallback."""
        # Sort prefixes by length (descending) for longest-prefix-first matching
        self._prefixes.sort(key=lambda x: len(x[0]), reverse=True)
    
    def lookup(self, mac: Any) -> Optional[str]:
        """Find vendor for MAC using trie lookup with longest prefix match."""
        norm = normalize_mac(mac)
        if norm is None:
            return None
        
        # Try trie lookup first
        result = self._trie_lookup(norm)
        if result is not None:
            return result
        
        # Fallback to binary search for edge cases
        return self._binary_search_lookup(norm)
    
    def _trie_lookup(self, norm_mac: str) -> Optional[str]:
        """Lookup using trie structure."""
        node = self._root
        best_match = None
        
        for char in norm_mac.replace(":", ""):
            if char in node.children:
                node = node.children[char]
                if node.vendor is not None:
                    best_match = node.vendor
            else:
                break
        
        return best_match
    
    def _binary_search_lookup(self, norm_mac: str) -> Optional[str]:
        """Fallback lookup using binary search on sorted prefixes."""
        if not self._prefixes:
            return None
        
        mac_clean = norm_mac.replace(":", "")
        
        # Try each possible prefix length (6, 8, 10, 12, 14, 16 chars for MAC)
        for length in range(6, min(len(mac_clean) + 2, 18), 2):
            prefix = mac_clean[:length]
            # Binary search for exact prefix match
            index = bisect.bisect_left(self._prefixes, (prefix, ""))
            if index < len(self._prefixes) and self._prefixes[index][0] == prefix:
                return self._prefixes[index][1]
        
        return None


class Enricher:
    """Annotates readings using local OUI/tracker intelligence."""

    def __init__(self, data_file: Optional[str] = None):
        self._tracker_patterns: List[str] = list(_DEFAULT_TRACKER_NAME_PATTERNS)
        self._tracker_vendors: List[str] = list(_DEFAULT_TRACKER_VENDORS)
        
        # Initialize optimized OUI lookup
        self._oui_lookup = OUILookup()
        
        # Add built-in OUI vendors
        for prefix, vendor in _DEFAULT_OUI_VENDORS.items():
            self._oui_lookup.add_prefix(prefix, vendor)

        if data_file:
            path = Path(data_file)
            if path.exists():
                self._load(path)
            else:
                logger.warning(f"Enrichment file not found: {data_file} — using built-in seed data")
        
        # Build the trie after all prefixes are added
        self._oui_lookup.build()

    def _load(self, path: Path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        
        # Add OUI vendors to lookup
        for prefix, vendor in (data.get("oui_vendors") or {}).items():
            self._oui_lookup.add_prefix(str(prefix).strip().lower(), str(vendor))
        
        self._tracker_patterns.extend(
            str(p).lower() for p in data.get("tracker_name_patterns") or []
        )
        self._tracker_vendors.extend(
            str(v).lower() for v in data.get("tracker_vendors") or []
        )
        
        # Rebuild trie with new data
        self._oui_lookup.build()
        
        logger.info(
            f"Enrichment data loaded: {len(self._oui_lookup._prefixes)} OUI prefixes, "
            f"{len(self._tracker_patterns)} tracker name patterns"
        )

    def vendor(self, mac: Any) -> Optional[str]:
        """Vendor name for a MAC's OUI prefix, or None if unknown."""
        return self._oui_lookup.lookup(mac)

    def _tracker_name(self, name: Any) -> bool:
        if not name:
            return False
        lowered = str(name).lower()
        return any(p in lowered for p in self._tracker_patterns)

    def enrich_wifi(self, net: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of a WiFi network dict with enrichment fields added."""
        out = dict(net)
        mac = out.get("BSSID") or out.get("bssid")
        out["vendor"] = self.vendor(mac)
        out["mac_randomized"] = mac_is_randomized(mac)
        return out

    def enrich_bluetooth(self, dev: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of a BT device dict with enrichment fields added."""
        out = dict(dev)
        mac = out.get("address") or out.get("mac") or out.get("BLUETOOTH_ADDRESS")
        vendor = self.vendor(mac)
        name_match = self._tracker_name(out.get("name"))
        out["vendor"] = vendor
        out["mac_randomized"] = mac_is_randomized(mac)
        out["tracker_name_match"] = name_match
        out["is_tracker"] = name_match or (
            vendor is not None and vendor.lower() in self._tracker_vendors
        )
        return out
