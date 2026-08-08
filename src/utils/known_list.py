"""Timestamped "known entity" lists with age-based pruning.

Sensors and the remote-BLE ingest path each track addresses they have already
seen, so a *new* device stands out. Kept as a plain set, that list only grows —
a café you visited once keeps diluting the "new AP" signal months later. This
stores ``address -> last_seen_epoch`` instead, and prunes entries older than a
configurable window so the list reflects a rolling recent history.

On-disk format is one ``address<TAB>epoch`` per line. Legacy files (bare
address per line) load with a last-seen of "now", so upgrading never spuriously
re-flags every previously-known device as new.
"""

import time
from pathlib import Path
from typing import Dict


def load_known(path: Path) -> Dict[str, float]:
    """Load an ``address -> last_seen_epoch`` map from ``path``.

    Missing file returns an empty map. Legacy bare-address lines are accepted
    and dated to now, so a first load after upgrading treats them as recent.
    """
    if not path.exists():
        return {}
    now = time.time()
    out: Dict[str, float] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        addr, _, ts = line.partition("\t")
        addr = addr.strip().lower()
        if not addr:
            continue
        try:
            out[addr] = float(ts) if ts else now
        except ValueError:
            out[addr] = now
    return out


def prune_known(known: Dict[str, float], max_age_days: int) -> Dict[str, float]:
    """Drop entries older than ``max_age_days`` (``0`` disables pruning)."""
    if max_age_days <= 0:
        return known
    cutoff = time.time() - (max_age_days * 86400)
    return {addr: ts for addr, ts in known.items() if ts >= cutoff}


def save_known(path: Path, known: Dict[str, float]) -> None:
    """Persist an ``address -> last_seen_epoch`` map as ``address<TAB>epoch``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{addr}\t{ts:.0f}" for addr, ts in sorted(known.items())]
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
