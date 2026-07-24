"""Durable, queryable event store backed by SQLite (standard library only).

Persists detections and other forensic/audit events into a single ``events``
table so history survives restarts and can be filtered and aggregated. It
complements — it does not replace — the tamper-evident forensic JSONL and the
signed, hash-chained audit log, which remain the authoritative record; this
store is the fast, queryable index over that history.

All queries are parameterized. The only values interpolated into SQL are
column/aggregate choices drawn from fixed allow-lists, never caller input, so
there is no injection surface (and no raw-SQL endpoint is exposed).
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,      -- ISO-8601 UTC
    type        TEXT NOT NULL,      -- 'detection', 'tamper', 'boot', ...
    severity    INTEGER,
    sensor_type TEXT,
    sensor_id   TEXT,
    confidence  REAL,
    description TEXT,
    data        TEXT NOT NULL       -- full JSON payload
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_sensor_type ON events(sensor_type);
"""

#: Allowed analytics time buckets → the ISO-timestamp prefix length to group on.
_BUCKETS = {"hour": 13, "day": 10, "month": 7}

#: Hard cap on how many rows a single query may return, so an authenticated
#: caller cannot pull an unbounded result set into memory.
MAX_LIMIT = 1000


class EventStore:
    """SQLite-backed store of detections and forensic/audit events."""

    enabled = True

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # check_same_thread=False + a lock: sensors record from several threads.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def record(
        self,
        event_type: str,
        data: Dict[str, Any],
        severity: Optional[int] = None,
        ts: Optional[str] = None,
    ) -> None:
        """Persist one event, extracting queryable columns from ``data``.

        Signature matches :class:`ForensicLogger`'s ``on_write`` hook, so every
        forensic event is mirrored here automatically.
        """
        data = data or {}
        row_ts = ts or _iso_or_none(data.get("timestamp")) or datetime.now(timezone.utc).isoformat()
        sev = severity if severity is not None else data.get("severity")
        with self._lock:
            self._conn.execute(
                "INSERT INTO events "
                "(ts, type, severity, sensor_type, sensor_id, confidence, description, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    row_ts, event_type, sev,
                    data.get("sensor_type"), data.get("sensor_id"),
                    data.get("confidence"), data.get("description"),
                    json.dumps(data, sort_keys=True),
                ),
            )
            self._conn.commit()

    def add_detection(self, detection: Dict[str, Any]) -> None:
        """Convenience wrapper for recording a detection dict."""
        self.record("detection", detection, severity=detection.get("severity"))

    def iter_all(
        self,
        event_type: Optional[str] = None,
        min_severity: Optional[int] = None,
        sensor_type: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        text: Optional[str] = None,
        batch: int = 1000,
    ):
        """Yield *every* matching event (oldest first), not just a page.

        Unlike :meth:`recent` (bounded by ``MAX_LIMIT`` for API responses), this
        streams the full matching population via keyset pagination on ``id``, so
        aggregations like ATT&CK coverage represent all events without capping
        or loading the whole table into memory. Each batch is fetched under the
        lock so writers are never blocked for the length of a full scan.
        """
        where, base_params = self._filters(
            event_type, min_severity, sensor_type, since, until, text
        )
        keyset = "AND id > ?" if where else "WHERE id > ?"
        # `where`/`keyset` are static fragments; all values are bound params.
        sql = f"SELECT * FROM events {where} {keyset} ORDER BY id ASC LIMIT ?"  # nosec B608
        last_id = 0
        page = max(1, int(batch))
        while True:
            with self._lock:
                rows = self._conn.execute(sql, [*base_params, last_id, page]).fetchall()
            if not rows:
                return
            for row in rows:
                yield _row_to_dict(row)
            last_id = rows[-1]["id"]
            if len(rows) < page:
                return

    def recent(
        self,
        limit: int = 50,
        event_type: Optional[str] = None,
        min_severity: Optional[int] = None,
        sensor_type: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        text: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return up to ``limit`` matching events, newest first."""
        where, params = self._filters(event_type, min_severity, sensor_type, since, until, text)
        params.append(min(max(1, int(limit)), MAX_LIMIT))
        # `where` is built only from static "col ? " fragments; all values are
        # bound parameters, so this is not user-controlled SQL.
        sql = f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?"  # nosec B608
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]

    def summary(
        self, since: Optional[str] = None, until: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return total and per-severity/type/sensor counts over the window."""
        # `where` holds only static "col ? " fragments (values are bound params).
        where, params = self._filters(event_type, None, None, since, until, None)
        with self._lock:
            total = self._conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]  # nosec B608
            by_sev = self._conn.execute(
                f"SELECT severity, COUNT(*) n FROM events {where} GROUP BY severity", params  # nosec B608
            ).fetchall()
            by_type = self._conn.execute(
                f"SELECT type, COUNT(*) n FROM events {where} GROUP BY type", params  # nosec B608
            ).fetchall()
            by_sensor = self._conn.execute(
                f"SELECT sensor_type, COUNT(*) n FROM events {where} GROUP BY sensor_type", params  # nosec B608
            ).fetchall()
        return {
            "total": total,
            "by_severity": {str(r["severity"]): r["n"] for r in by_sev if r["severity"] is not None},
            "by_type": {r["type"]: r["n"] for r in by_type},
            "by_sensor_type": {r["sensor_type"]: r["n"] for r in by_sensor if r["sensor_type"] is not None},
        }

    def analytics(
        self, bucket: str = "day", event_type: Optional[str] = "detection",
        since: Optional[str] = None, until: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return time-bucketed event counts plus the most frequent descriptions."""
        length = _BUCKETS.get(bucket, _BUCKETS["day"])
        where, params = self._filters(event_type, None, None, since, until, None)
        with self._lock:
            # ``length`` comes from the _BUCKETS allow-list and ``where`` from
            # static fragments; all caller values are bound parameters.
            counts = self._conn.execute(
                f"SELECT substr(ts, 1, {length}) AS bucket, COUNT(*) AS n "  # nosec B608
                f"FROM events {where} GROUP BY bucket ORDER BY bucket", params
            ).fetchall()
            top_where = where + (" AND" if where else " WHERE") + " description IS NOT NULL"
            top = self._conn.execute(
                f"SELECT description, COUNT(*) AS n FROM events {top_where} "  # nosec B608
                "GROUP BY description ORDER BY n DESC, description LIMIT 10", params
            ).fetchall()
        return {
            "bucket": bucket,
            "counts": [{"bucket": r["bucket"], "count": r["n"]} for r in counts],
            "top_descriptions": [{"description": r["description"], "count": r["n"]} for r in top],
        }

    def count(self) -> int:
        """Total number of stored events."""
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self) -> None:
        """Close the underlying connection."""
        with self._lock:
            self._conn.close()

    @staticmethod
    def _filters(event_type, min_severity, sensor_type, since, until, text):
        clauses: List[str] = []
        params: List[Any] = []
        if event_type is not None:
            clauses.append("type = ?")
            params.append(event_type)
        if min_severity is not None:
            clauses.append("severity >= ?")
            params.append(int(min_severity))
        if sensor_type is not None:
            clauses.append("sensor_type = ?")
            params.append(sensor_type)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        if text:
            clauses.append("description LIKE ?")
            params.append(f"%{text}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params


class NullEventStore:
    """No-op store used when persistence is disabled (``event_db`` unset)."""

    enabled = False

    def record(self, *args: Any, **kwargs: Any) -> None:
        """Ignore the event."""

    def add_detection(self, *args: Any, **kwargs: Any) -> None:
        """Ignore the detection."""

    def recent(self, *args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        """Return no events."""
        return []

    def summary(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Return an empty summary."""
        return {"total": 0, "by_severity": {}, "by_type": {}, "by_sensor_type": {}}

    def analytics(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Return empty analytics."""
        return {"bucket": kwargs.get("bucket", "day"), "counts": [], "top_descriptions": []}

    def count(self) -> int:
        """Return zero."""
        return 0

    def close(self) -> None:
        """Nothing to close."""


def _iso_or_none(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["data"] = json.loads(d["data"])
    except (TypeError, json.JSONDecodeError):
        pass
    return d
