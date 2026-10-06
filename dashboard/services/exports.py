"""Export adapters for MIRAGE threat observations (T4).

Structured JSON export is always available. STIX 2.1 / SIEM webhooks are
interfaces here: a real STIX/TAXII library can be plugged in later
without touching call sites (dependency-free by design — see
docs/integration/T4_API_CONTRACT.md §5).

Security: exports contain only whitelisted ThreatObservation fields.
No host paths outside the VFS, no environment variables, no secrets.
A webhook, if configured, requires explicit MIRAGE_WEBHOOK_URL, must be
http(s), is bound to a timeout, and sends only redacted observations.
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Optional, Protocol

from dashboard.services.models import ThreatObservation


class ExportDestination(Protocol):
    """Interface a real STIX/TAXII or SIEM library can implement."""

    def send(self, observations: list[ThreatObservation]) -> dict:
        ...


class JsonFileExporter(ExportDestination):
    """Writes observations as structured JSON (always available)."""

    def __init__(self, output_path: Path | str):
        self._path = Path(output_path)

    def send(self, observations: list[ThreatObservation]) -> dict:
        payload = [o.to_export_dict() for o in observations]
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(payload, indent=2))
        return {
            "format": "json",
            "path": str(self._path),
            "count": len(payload),
        }


class WebhookExporter(ExportDestination):
    """POSTs redacted observations to an explicitly-configured webhook.

    Refuses to send unless MIRAGE_WEBHOOK_URL is set and http(s); content is
    limited to the whitelisted export fields; short hard timeout.
    """

    def __init__(self, url: Optional[str] = None, timeout: float = 5.0):
        self._url = (url or os.getenv("MIRAGE_WEBHOOK_URL") or "").strip()
        self._timeout = timeout

    def send(self, observations: list[ThreatObservation]) -> dict:
        if not self._url:
            return {"status": "skipped", "reason": "MIRAGE_WEBHOOK_URL not configured"}
        if not (self._url.startswith("http://") or self._url.startswith("https://")):
            return {"status": "skipped", "reason": "webhook URL must be http(s)"}
        payload = json.dumps([o.to_export_dict() for o in observations]).encode()
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return {"status": "sent", "http_status": resp.status, "count": len(observations)}
        except Exception as exc:
            return {"status": "failed", "reason": str(exc)[:120]}


def to_json_events(observations: list[ThreatObservation]) -> str:
    """Structured JSON security-event export (no dependencies)."""
    return json.dumps([o.to_export_dict() for o in observations], indent=2)


class STIXExportAdapter(ExportDestination):
    """Placeholder for a real STIX 2.1 bundle emitter.

    The whitelisted export dict (ThreatObservation.to_export_dict) is the
    input contract; a stix2-based implementation maps:
        category + technique_id  -> Sighting + AttackPattern
        session_id               -> SDO observed-data ref
        evidence (redacted)      -> description
    """

    def send(self, observations: list[ThreatObservation]) -> dict:
        return {
            "format": "stix2.1",
            "status": "not-implemented",
            "message": "plug in a stix2 bundle emitter on to_export_dict()",
            "count": len(observations),
        }


class SIEMExportAdapter(ExportDestination):
    """Placeholder for a SIEM (CEF/LEEF) forwarder with the same contract."""

    def send(self, observations: list[ThreatObservation]) -> dict:
        return {
            "format": "cef",
            "status": "not-implemented",
            "message": "plug in a CEF/LEEF forwarder on to_export_dict()",
            "count": len(observations),
        }
