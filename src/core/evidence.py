"""Forensic evidence export with provenance, hashing, and signatures.

Turns TIGRESS forensic records into a self-contained, tamper-evident evidence
bundle following digital-evidence-preservation practice (NIST IR 8387 §3.2 and
the NIJ Digital Evidence Policies & Procedures Manual):

  * a NIST-approved SHA-256 hash of the evidence, recorded in a **manifest that
    is stored separately** from the data itself;
  * an optional ECDSA signature over that manifest;
  * documented **chain of custody / provenance** — which tool and version
    produced it, on which host, over which capture window, and how.
"""

import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.version import __version__

_CHUNK = 65536


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in bounded chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def provenance(extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build the chain-of-custody provenance block for an artifact.

    Records the producing tool and version, the host, and a UTC creation
    timestamp so every artifact is attributable to the software and machine
    that created it.
    """
    prov = {
        "tool": "TIGRESS",
        "version": __version__,
        "host": socket.gethostname(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        prov.update(extra)
    return prov


def _record_timestamp(record: Dict[str, Any]) -> Optional[str]:
    """Best-effort extraction of a record's ISO timestamp, if any."""
    data = record.get("data")
    if isinstance(data, dict):
        ts = data.get("timestamp")
        if isinstance(ts, str):
            return ts
    return None


def _in_window(record: Dict[str, Any], since: Optional[str], until: Optional[str]) -> bool:
    """True if the record falls within [since, until].

    Records without a timestamp are always included — they cannot be excluded
    on time and dropping them would lose context.
    """
    if since is None and until is None:
        return True
    ts = _record_timestamp(record)
    if ts is None:
        return True
    if since is not None and ts < since:
        return False
    if until is not None and ts > until:
        return False
    return True


class EvidenceExporter:
    """Export forensic records into a signed, hashed evidence bundle."""

    def __init__(self, forensic_log: str, signer: Optional[Any] = None):
        """``signer`` is an optional object exposing ``sign_bytes`` and
        ``public_key_b64`` (e.g. :class:`~src.security.audit_log.AuditLog`)."""
        self.forensic_log = Path(forensic_log)
        self.signer = signer

    def _read_records(
        self, since: Optional[str], until: Optional[str],
        event_types: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        if not self.forensic_log.exists():
            return records
        types = set(event_types) if event_types else None
        with open(self.forensic_log) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if types is not None and rec.get("type") not in types:
                    continue
                if not _in_window(rec, since, until):
                    continue
                records.append(rec)
        return records

    def export(
        self,
        output_dir: str,
        since: Optional[str] = None,
        until: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Write an evidence bundle to ``output_dir`` and return its manifest.

        The bundle contains ``evidence.jsonl`` (the selected records),
        ``manifest.json`` (provenance + the separately-stored SHA-256),
        ``manifest.sig`` (present only when a signer is configured), and
        ``CHAIN_OF_CUSTODY.txt`` describing how it was produced.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        records = self._read_records(since, until, event_types)
        evidence_path = out / "evidence.jsonl"
        with open(evidence_path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec, sort_keys=True) + "\n")

        digest = sha256_file(evidence_path)
        manifest: Dict[str, Any] = {
            "provenance": provenance({"case_id": case_id} if case_id else None),
            "capture_window": {"since": since, "until": until},
            "event_types": event_types,
            "source": str(self.forensic_log),
            "evidence_file": evidence_path.name,
            "record_count": len(records),
            "sha256": digest,
            "hash_algorithm": "SHA-256",
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
        (out / "manifest.json").write_bytes(manifest_bytes)

        signed = False
        if self.signer is not None:
            signature = {
                "signature": self.signer.sign_bytes(manifest_bytes),
                "public_key": self.signer.public_key_b64,
                "algorithm": "ECDSA-SHA512",
                "signed_file": "manifest.json",
            }
            (out / "manifest.sig").write_text(json.dumps(signature, indent=2))
            signed = True

        (out / "CHAIN_OF_CUSTODY.txt").write_text(self._custody_note(manifest, signed))
        manifest["signed"] = signed
        manifest["output_dir"] = str(out)
        return manifest

    @staticmethod
    def _custody_note(manifest: Dict[str, Any], signed: bool) -> str:
        prov = manifest["provenance"]
        window = manifest["capture_window"]
        lines = [
            "TIGRESS Evidence Bundle — Chain of Custody",
            "=" * 44,
            f"Produced by : {prov['tool']} {prov['version']}",
            f"Host        : {prov['host']}",
            f"Generated   : {prov['generated_at']}",
            f"Case ID     : {prov.get('case_id') or '(none)'}",
            f"Source log  : {manifest['source']}",
            f"Window      : {window['since'] or 'start'} .. {window['until'] or 'end'}",
            f"Records     : {manifest['record_count']}",
            f"SHA-256     : {manifest['sha256']}  (stored separately in manifest.json)",
            f"Signature   : {'ECDSA-SHA512 (manifest.sig)' if signed else 'unsigned'}",
            "",
            "How created : records were selected from the source forensic log by",
            "              the criteria above, written to evidence.jsonl, then",
            "              hashed. To verify, recompute the SHA-256 of",
            "              evidence.jsonl and compare it to manifest.json; if a",
            "              signature is present, verify manifest.sig against the",
            "              included public key.",
        ]
        return "\n".join(lines) + "\n"
