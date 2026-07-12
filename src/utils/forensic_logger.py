"""Append-only forensic JSONL logging with rotation and retention.

Each write is fsynced. When ``max_bytes`` is set the active log is rotated
under a dated, uniform naming convention (NIJ Storage & Retention practice) and
a detached ``.sha256`` sidecar — the hash stored *separately* from the data,
per NIST IR 8387 §3.2.1 — is written next to the rotated file (optionally with
an ECDSA signature). Rotated files older than ``retention_days`` are pruned.
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_CHUNK = 65536


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


class ForensicLogger:
    """Append-only JSONL forensic log with optional rotation and retention."""

    def __init__(
        self,
        log_path: str,
        max_bytes: int = 0,
        retention_days: int = 0,
        signer: Optional[Any] = None,
    ):
        """``max_bytes`` (0 disables) rotates the log once it would be exceeded.

        ``retention_days`` (0 disables) prunes rotated files older than that.
        ``signer`` is an optional object exposing ``sign_bytes``/``public_key_b64``
        (e.g. :class:`~src.security.audit_log.AuditLog`) used to sign the sidecar.
        """
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(exist_ok=True, parents=True)
        self.max_bytes = int(max_bytes)
        self.retention_days = int(retention_days)
        self.signer = signer

    def log(self, event_type: str, data: Dict[str, Any]):
        """Append one fsynced JSONL record, rotating first if needed."""
        entry = json.dumps({"type": event_type, "data": data})
        line = entry + "\n"
        self._maybe_rotate(len(line.encode()))
        try:
            with open(self.log_path, "a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.error(f"Forensic log write failed: {e}")

    def _maybe_rotate(self, incoming_bytes: int):
        if self.max_bytes <= 0 or not self.log_path.exists():
            return
        if self.log_path.stat().st_size + incoming_bytes <= self.max_bytes:
            return
        self.rotate()

    def rotate(self) -> Optional[Path]:
        """Rotate the active log to a dated file with a detached hash sidecar.

        Returns the rotated file path, or None if there was nothing to rotate.
        """
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return None
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated = self.log_path.with_name(
            f"{self.log_path.stem}_{stamp}{self.log_path.suffix}"
        )
        # Avoid clobbering if two rotations land in the same second.
        counter = 1
        while rotated.exists():
            rotated = self.log_path.with_name(
                f"{self.log_path.stem}_{stamp}_{counter}{self.log_path.suffix}"
            )
            counter += 1
        try:
            self.log_path.rename(rotated)
        except OSError as e:
            logger.error(f"Forensic log rotation failed: {e}")
            return None
        self._write_sidecar(rotated)
        self._prune()
        return rotated

    def _write_sidecar(self, rotated: Path):
        """Write the detached SHA-256 (and optional signature) for a rotated file."""
        try:
            digest = _sha256_file(rotated)
            sidecar = {"file": rotated.name, "sha256": digest, "algorithm": "SHA-256"}
            if self.signer is not None:
                sidecar["signature"] = self.signer.sign_bytes(digest.encode())
                sidecar["public_key"] = self.signer.public_key_b64
                sidecar["signature_algorithm"] = "ECDSA-SHA512"
            rotated.with_suffix(rotated.suffix + ".sha256").write_text(
                json.dumps(sidecar, indent=2)
            )
        except OSError as e:
            logger.error(f"Forensic sidecar write failed: {e}")

    def _prune(self):
        """Delete rotated logs (and sidecars) older than the retention window."""
        if self.retention_days <= 0:
            return
        cutoff = time.time() - self.retention_days * 86400
        pattern = f"{self.log_path.stem}_*{self.log_path.suffix}"
        for path in self.log_path.parent.glob(pattern):
            if path.suffix == ".sha256":
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    sidecar = path.with_suffix(path.suffix + ".sha256")
                    if sidecar.exists():
                        sidecar.unlink()
            except OSError as e:
                logger.error(f"Forensic log prune failed for {path}: {e}")
