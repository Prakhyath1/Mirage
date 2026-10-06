"""Read-only repository over the two MIRAGE data planes.

This is the ONLY module in the dashboard that touches a database or the
backend API. UI components receive typed view models; they never see a
connection, a cursor, or a raw row.

Two planes, deliberately separate files (T1 chose the split — the two
schemas are incompatible):

    foundation  T1 runtime store, data/mirage_foundation.db
                sessions/commands/command_results/events via app.storage
    pipeline    T3/T2 deception pipeline, data/mirage.db
                sessions/logs/virtual_files/events via legacy app.db

Every method:
- opens a short-lived read-only connection (no shared mutable state),
- returns typed view models or plain lists,
- raises :class:`MirageDataUnavailable` (or returns empty) so a broken
  plane never takes the whole dashboard down,
- never writes: the dashboard is read-heavy and cannot mutate attacker
  state (see security tests).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

from dashboard.services.models import (
    PLANE_FOUNDATION,
    PLANE_PIPELINE,
    AgentObservation,
    DashboardCommand,
    DashboardSecurityEvent,
    DashboardSession,
    HoneytokenEvent,
    MitreObservation,
    SystemHealth,
    ThreatObservation,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]

# Same marker set as T1's config — values under these keys are never
# surfaced by the dashboard.
_SECRET_MARKERS = ("password", "secret", "token", "api_key", "credential")


class MirageDataUnavailable(RuntimeError):
    """A data plane (or the backend API) could not be read at all."""


def _redact(value: str, limit: int = 200) -> str:
    """Bounded, marker-redacted copy of untrusted text for display."""
    text = str(value)
    lowered = text.lower()
    for marker in _SECRET_MARKERS:
        idx = lowered.find(marker)
        # Redact "key=value" style secrets that appear in attacker text or
        # event details without hiding the fact a secret was touched.
        while idx != -1:
            eq = text.find("=", idx)
            nl = text.find("\n", idx)
            end = eq if 0 <= eq < (nl if nl != -1 else len(text)) else (nl if nl != -1 else len(text))
            text = text[:idx] + text[idx:end].split("=")[0] + "=***REDACTED***" + text[end:]
            break
        break
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _safe_metadata(payload: Any) -> dict:
    """JSON payload -> bounded, secret-stripped dict (never raises)."""
    if not payload:
        return {}
    if isinstance(payload, dict):
        data = payload
    else:
        try:
            data = json.loads(payload)
            if not isinstance(data, dict):
                return {}
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
    out: dict[str, Any] = {}
    for key, value in data.items():
        k = str(key)
        if any(m in k.lower() for m in _SECRET_MARKERS):
            out[k] = "[redacted]"
            continue
        out[k] = _redact(value, limit=120) if isinstance(value, (str, int, float, bool)) or value is None else str(value)[:120]
    return out


def _foundation_db_path() -> Path:
    """T1's configured foundation DB path (MIRAGE_DB_PATH aware)."""
    env = os.getenv("MIRAGE_DB_PATH")
    if env:
        return Path(env)
    return _REPO_ROOT / "data" / "mirage_foundation.db"


def _pipeline_db_path() -> Path:
    """Legacy pipeline DB path — monkeypatchable by tests (T3's db.DB_PATH)."""
    try:
        from app import db as pipeline_db

        return Path(pipeline_db.DB_PATH)
    except Exception:
        return _REPO_ROOT / "data" / "mirage.db"


def _read_rows(db_path: Path, query: str, params: tuple = ()) -> list[dict]:
    """Run one read-only query; every failure becomes MirageDataUnavailable."""
    if not db_path or not Path(db_path).exists():
        raise MirageDataUnavailable(f"database not found: {Path(db_path).name}")
    conn = None
    try:
        conn = sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True, timeout=3.0)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        raise MirageDataUnavailable(str(exc)[:200]) from exc
    finally:
        if conn is not None:
            conn.close()


class MirageRepository:
    """All dashboard data access. Stateless; cheap to construct."""

    # ------------------------------------------------------------------ #
    # sessions
    # ------------------------------------------------------------------ #

    def list_sessions(self, limit: int = 200) -> list[DashboardSession]:
        """Sessions from both planes, newest first."""
        sessions: list[DashboardSession] = []
        sessions.extend(self._pipeline_sessions(limit))
        sessions.extend(self._foundation_sessions(limit))
        sessions.sort(
            key=lambda s: (s.last_seen or s.created_at or 0.0),
            reverse=True,
        )
        return sessions[:limit]

    def get_session(self, session_id: str) -> Optional[DashboardSession]:
        found = [s for s in self.list_sessions(500) if s.session_id == session_id]
        return found[0] if found else None

    def _pipeline_sessions(self, limit: int) -> list[DashboardSession]:
        try:
            rows = _read_rows(
                _pipeline_db_path(),
                """
                SELECT s.session_id, s.created_at, s.last_seen, s.cwd,
                       s.threat_score, s.threat_level, s.containment_active,
                       (SELECT COUNT(*) FROM logs l WHERE l.session_id = s.session_id) AS command_count
                FROM sessions s ORDER BY s.last_seen DESC LIMIT ?
                """,
                (limit,),
            )
        except MirageDataUnavailable:
            return []
        return [
            DashboardSession(
                session_id=r.get("session_id", ""),
                plane=PLANE_PIPELINE,
                created_at=r.get("created_at"),
                last_seen=r.get("last_seen"),
                status="ACTIVE" if r.get("last_seen") and time.time() - r["last_seen"] < 300 else "IDLE",
                cwd=r.get("cwd") or "",
                command_count=int(r.get("command_count") or 0),
                threat_score=int(r.get("threat_score") or 0),
                threat_level=r.get("threat_level") or "Low",
                containment_active=bool(r.get("containment_active")),
            )
            for r in rows
        ]

    def _foundation_sessions(self, limit: int) -> list[DashboardSession]:
        try:
            rows = _read_rows(
                _foundation_db_path(),
                """
                SELECT session_id, created_at, updated_at, status,
                       source_address, username, cwd
                FROM sessions ORDER BY updated_at DESC LIMIT ?
                """,
                (limit,),
            )
        except MirageDataUnavailable:
            return []
        return [
            DashboardSession(
                session_id=r.get("session_id", ""),
                plane=PLANE_FOUNDATION,
                created_at=r.get("created_at"),
                last_seen=r.get("updated_at"),
                status=r.get("status") or "CREATED",
                source_address=r.get("source_address") or "",
                username=r.get("username") or "",
                cwd=r.get("cwd") or "",
                command_count=0,
                threat_score=0,
                threat_level="Low",
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ #
    # commands (session history -> replay)
    # ------------------------------------------------------------------ #

    def list_commands(self, session_id: str, limit: int = 200) -> list[DashboardCommand]:
        """Chronological (oldest first) command/response pairs for replay."""
        out: list[DashboardCommand] = list(self._pipeline_commands(session_id, limit))
        out.extend(self._foundation_commands(session_id, limit))
        out.sort(key=lambda c: (c.timestamp or 0.0, c.plane), reverse=False)
        return out

    def recent_commands(self, limit: int = 100) -> list[DashboardCommand]:
        """Newest commands across all sessions and both planes (Overview
        command-log strip; T3's pinned third dataframe)."""
        out: list[DashboardCommand] = []
        for session in self.list_sessions(limit=500):
            out.extend(self.list_commands(session.session_id, limit))
        out.sort(key=lambda c: (c.timestamp or 0.0), reverse=True)
        return out[:limit]

    def _pipeline_commands(self, session_id: str, limit: int) -> list[DashboardCommand]:
        try:
            rows = _read_rows(
                _pipeline_db_path(),
                """
                SELECT command, output, source, timestamp FROM logs
                WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?
                """,
                (session_id, limit),
            )
        except MirageDataUnavailable:
            return []
        return [
            DashboardCommand(
                session_id=session_id,
                plane=PLANE_PIPELINE,
                timestamp=r.get("timestamp"),
                raw_command=r.get("command") or "",
                output=r.get("output") or "",
                source=r.get("source") or "",
            )
            for r in rows
        ]

    def _foundation_commands(self, session_id: str, limit: int) -> list[DashboardCommand]:
        try:
            rows = _read_rows(
                _foundation_db_path(),
                """
                SELECT c.command_id, c.raw_command, c.timestamp, c.working_directory,
                       cr.output, cr.result_type, cr.exit_code
                FROM commands c
                LEFT JOIN command_results cr ON cr.command_id = c.command_id
                WHERE c.session_id = ?
                ORDER BY c.timestamp DESC LIMIT ?
                """,
                (session_id, limit),
            )
        except MirageDataUnavailable:
            return []
        return [
            DashboardCommand(
                session_id=session_id,
                plane=PLANE_FOUNDATION,
                timestamp=r.get("timestamp"),
                raw_command=r.get("raw_command") or "",
                output=r.get("output") or "",
                source="foundation",
                command_id=r.get("command_id"),
                result_type=r.get("result_type"),
                working_directory=r.get("working_directory") or "",
                exit_code=int(r["exit_code"]) if r.get("exit_code") is not None else None,
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ #
    # events
    # ------------------------------------------------------------------ #

    def list_events(
        self,
        limit: int = 200,
        event_type: Optional[str] = None,
        session_id: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[float] = None,
    ) -> list[DashboardSecurityEvent]:
        """Security/audit events from both planes, newest first."""
        out: list[DashboardSecurityEvent] = []
        out.extend(self._pipeline_events(limit, event_type, session_id, since))
        out.extend(self._foundation_events(limit, event_type, session_id, severity, since))
        out.sort(key=lambda e: (e.timestamp or 0.0), reverse=True)
        return out[:limit]

    def _pipeline_events(
        self, limit, event_type, session_id, since
    ) -> list[DashboardSecurityEvent]:
        query = "SELECT event_type, session_id, details, timestamp FROM events"
        clauses, params = [], []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            rows = _read_rows(
                _pipeline_db_path(),
                query + where + " ORDER BY timestamp DESC LIMIT ?",
                tuple(params) + (limit,),
            )
        except MirageDataUnavailable:
            return []
        events = []
        for r in rows:
            etype = r.get("event_type") or ""
            events.append(
                DashboardSecurityEvent(
                    event_type=etype,
                    session_id=r.get("session_id") or "",
                    plane=PLANE_PIPELINE,
                    timestamp=r.get("timestamp"),
                    severity=_PIPELINE_EVENT_SEVERITY.get(etype, "INFO"),
                    details=_redact(r.get("details") or ""),
                )
            )
        return events

    def _foundation_events(
        self, limit, event_type, session_id, severity, since
    ) -> list[DashboardSecurityEvent]:
        query = (
            "SELECT event_id, session_id, event_type, timestamp, severity, source, payload FROM events"
        )
        clauses, params = [], []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        try:
            rows = _read_rows(
                _foundation_db_path(),
                query + where + " ORDER BY timestamp DESC LIMIT ?",
                tuple(params) + (limit,),
            )
        except MirageDataUnavailable:
            return []
        return [
            DashboardSecurityEvent(
                event_type=r.get("event_type") or "",
                session_id=r.get("session_id") or "",
                plane=PLANE_FOUNDATION,
                timestamp=r.get("timestamp"),
                severity=(r.get("severity") or "info").upper(),
                details=_redact(json.dumps(_safe_metadata(r.get("payload"))) if r.get("payload") else ""),
                event_id=r.get("event_id"),
                source=r.get("source") or "",
            )
            for r in rows
        ]

    def list_alerts(self, limit: int = 50) -> list[DashboardSecurityEvent]:
        """Only event types the backends themselves define as alert-worthy."""
        events = self.list_events(limit=500)
        return [e for e in events if e.is_alert_worthy][:limit]

    # ------------------------------------------------------------------ #
    # honeytokens (metadata only — never content)
    # ------------------------------------------------------------------ #

    def list_honeytokens(self, session_id: Optional[str] = None) -> list[HoneytokenEvent]:
        """Canary files from the pipeline plane. Content is never selected."""
        query = "SELECT DISTINCT path, is_honeytoken, session_id FROM virtual_files WHERE is_honeytoken = 1"
        params: tuple = ()
        if session_id:
            query += " AND session_id = ?"
            params = (session_id,)
        try:
            rows = _read_rows(_pipeline_db_path(), query, params)
        except MirageDataUnavailable:
            return []
        tokens = [
            HoneytokenEvent(
                path=r.get("path") or "",
                tripped=self._token_tripped(r.get("session_id") or "", r.get("path") or ""),
                is_honeytoken=True,
                session_id=r.get("session_id") or "",
            )
            for r in rows
        ]
        trips = {
            (e.session_id, self._trip_path(e.details))
            for e in self.list_events(event_type="HONEYTOKEN_ACCESS", limit=1000)
        }
        for t in tokens:
            if not t.tripped and (t.session_id, t.path) in trips:
                object.__setattr__(t, "tripped", True)
        return tokens

    @staticmethod
    def _trip_path(details: str) -> str:
        """HONEYTOKEN_ACCESS details carry 'Path: /home/admin/.env'."""
        marker = "Path: "
        if marker in details:
            return details.split(marker, 1)[1].strip()
        return details.strip()

    def _token_tripped(self, session_id: str, path: str) -> bool:
        try:
            rows = _read_rows(
                _pipeline_db_path(),
                "SELECT 1 FROM events WHERE session_id = ? AND event_type = 'HONEYTOKEN_ACCESS' LIMIT 1",
                (session_id,),
            )
        except MirageDataUnavailable:
            return False
        return bool(rows)

    # ------------------------------------------------------------------ #
    # agent observations (T2)
    # ------------------------------------------------------------------ #

    def list_agent_observations(
        self, session_id: Optional[str] = None, limit: int = 100
    ) -> list[AgentObservation]:
        events = self.list_events(limit=1000, session_id=session_id)
        obs = []
        for e in events:
            if not e.event_type.startswith("AGENT_"):
                continue
            meta = _safe_metadata(e.details if e.details.startswith("{") else "{}")
            obs.append(
                AgentObservation(
                    event_type=e.event_type,
                    session_id=e.session_id,
                    timestamp=e.timestamp,
                    details=_redact(e.details, limit=300),
                    action=meta.get("action") if isinstance(meta.get("action"), str) else None,
                    used_fallback=(meta.get("source") == "fallback") if "source" in meta else None,
                    confidence=None,
                )
            )
            if len(obs) >= limit:
                break
        return obs

    # ------------------------------------------------------------------ #
    # MITRE (T3 classifier is authoritative — T4 only renders)
    # ------------------------------------------------------------------ #

    def list_mitre_observations(self, limit: int = 200) -> list[MitreObservation]:
        """Group stored pipeline commands by T3's own classification.

        T4 never re-implements scoring: it calls T3's classifier module on
        commands the backend actually stored, then renders the documented
        category→technique presentation map. Commands T3 would classify
        SAFE produce no observation.
        """
        from dashboard.services.mitre_map import category_to_technique

        sessions = self._pipeline_sessions(limit)
        per_technique: dict[str, dict] = {}
        for s in sessions:
            for cmd in self._pipeline_commands(s.session_id, 100):
                category = self.classify_command(cmd.raw_command)
                technique = category_to_technique(category)
                if technique is None:
                    continue
                entry = per_technique.setdefault(
                    technique.technique_id,
                    {
                        "technique": technique,
                        "sessions": set(),
                        "examples": [],
                        "first": None,
                        "last": None,
                    },
                )
                entry["sessions"].add(s.session_id)
                if len(entry["examples"]) < 5:
                    entry["examples"].append(cmd.raw_command[:120])
                ts = cmd.timestamp
                if ts is not None:
                    entry["first"] = ts if entry["first"] is None else min(entry["first"], ts)
                    entry["last"] = ts if entry["last"] is None else max(entry["last"], ts)
        out = []
        for technique_id, entry in per_technique.items():
            technique = entry["technique"]
            out.append(
                MitreObservation(
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    category=technique.category,
                    session_ids=tuple(sorted(entry["sessions"])),
                    command_examples=tuple(entry["examples"]),
                    first_seen=entry["first"],
                    last_seen=entry["last"],
                    confidence=0.5 + 0.1 * min(3, len(entry["sessions"])),
                    session_count=len(entry["sessions"]),
                )
            )
        out.sort(key=lambda m: (-m.session_count, m.technique_id))
        return out[:limit]

    @staticmethod
    def classify_command(raw_command: str) -> str:
        """Ask T3's classifier (the authoritative one) for the category.

        Any failure degrades to UNKNOWN — the dashboard never guesses a
        better-sounding category."""
        try:
            from app import classifier
            from app.vfs import parser

            pipeline = parser.parse(raw_command)
            return classifier.classify(pipeline) if pipeline else "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    # ------------------------------------------------------------------ #
    # health (backend is authoritative for its own status)
    # ------------------------------------------------------------------ #

    def system_health(self) -> list[SystemHealth]:
        components: list[SystemHealth] = []
        now = time.time()

        # Foundation DB
        started = time.monotonic()
        try:
            _read_rows(_foundation_db_path(), "SELECT 1")
            components.append(
                SystemHealth(
                    component="Foundation database (T1)",
                    status="up",
                    detail=f"{_foundation_db_path().name}",
                    latency_ms=round((time.monotonic() - started) * 1000, 1),
                    checked_at=now,
                )
            )
        except MirageDataUnavailable as exc:
            components.append(
                SystemHealth(
                    component="Foundation database (T1)",
                    status="down",
                    detail=str(exc)[:120],
                    latency_ms=round((time.monotonic() - started) * 1000, 1),
                    checked_at=now,
                )
            )

        # Pipeline DB
        started = time.monotonic()
        try:
            _read_rows(_pipeline_db_path(), "SELECT 1")
            status = "up"
            detail = f"{_pipeline_db_path().name}"
        except MirageDataUnavailable as exc:
            status, detail = "down", str(exc)[:120]
        components.append(
            SystemHealth(
                component="Pipeline database (T3)",
                status=status,
                detail=detail,
                latency_ms=round((time.monotonic() - started) * 1000, 1),
                checked_at=now,
            )
        )

        # Backend API (best effort; read-only GET /health)
        components.append(self._api_health(now))

        # T2 LLM provider: derived from backend state only — a recent
        # AGENT_FALLBACK event means the provider was unreachable; a
        # recent successful decision means it answered. Absent data =>
        # unknown, never invented.
        llm_status, llm_detail = "unknown", "no agent events recorded"
        recent = self.list_events(limit=200)
        agent_events = [e for e in recent if e.event_type.startswith("AGENT_")]
        if agent_events:
            decisions = [e for e in agent_events if e.event_type == "AGENT_DECISION"]
            fallbacks = [e for e in agent_events if e.event_type == "AGENT_FALLBACK"]
            if fallbacks and not decisions:
                llm_status = "degraded"
                llm_detail = f"{len(fallbacks)} fallback(s), no successful decisions"
            elif decisions:
                llm_status = "up"
                llm_detail = f"{len(decisions)} decision(s) recorded"
            elif fallbacks:
                llm_status = "degraded"
                llm_detail = f"{len(fallbacks)} fallback(s) recorded"
        components.append(
            SystemHealth(component="LLM provider (T2)", status=llm_status, detail=llm_detail, checked_at=now)
        )

        # Dashboard itself (this code running is the check)
        components.append(
            SystemHealth(component="Dashboard (T4)", status="up", detail="rendering", checked_at=now)
        )

        # VFS/sandbox: derived from T3's pipeline DB presence + recent errors
        vfs_status = "up" if any(c.component.startswith("Pipeline") and c.is_healthy for c in components) else "down"
        components.append(
            SystemHealth(
                component="VFS / sandbox (T3)",
                status=vfs_status,
                detail="derived from pipeline database availability",
                checked_at=now,
            )
        )
        return components

    @staticmethod
    def _api_health(now: float) -> SystemHealth:
        import urllib.request

        url = os.getenv("MIRAGE_API_URL", "http://127.0.0.1:8000/health")
        started = time.monotonic()
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                ok = resp.status == 200
                body = resp.read(2048).decode("utf-8", "replace")
        except Exception as exc:
            return SystemHealth(
                component="MIRAGE API",
                status="down",
                detail=f"unreachable: {str(exc)[:80]}",
                latency_ms=round((time.monotonic() - started) * 1000, 1),
                checked_at=now,
            )
        return SystemHealth(
            component="MIRAGE API",
            status="up" if ok else "degraded",
            detail=body[:120],
            latency_ms=round((time.monotonic() - started) * 1000, 1),
            checked_at=now,
        )

    # ------------------------------------------------------------------ #
    # metrics (overview) — every value counts backend rows
    # ------------------------------------------------------------------ #

    def overview_metrics(self) -> dict[str, Any]:
        sessions = self.list_sessions(500)
        events = self.list_events(limit=1000)
        commands_total = sum(s.command_count for s in sessions if s.plane == PLANE_PIPELINE)
        commands_total += self._foundation_command_count()
        alerts = [e for e in events if e.is_alert_worthy]
        return {
            "active_sessions": sum(1 for s in sessions if s.is_active),
            "total_sessions": len(sessions),
            "commands_observed": commands_total,
            "security_events": len(events),
            "high_risk_sessions": sum(1 for s in sessions if s.threat_level == "High"),
            "honeytoken_triggers": sum(1 for e in events if e.event_type == "HONEYTOKEN_ACCESS"),
            "blocked_operations": sum(1 for e in events if e.event_type == "SANDBOX_BLOCK"),
            "llm_requests": sum(1 for e in events if e.event_type == "AGENT_DECISION"),
            "llm_failures": sum(
                1 for e in events if e.event_type in ("AGENT_FALLBACK", "AGENT_GUARDRAIL_REJECT")
            ),
            "metrics_alerts": len(alerts),
            "avg_session_duration": (
                sum(d for s in sessions if (d := s.duration_seconds) is not None)
                / max(1, sum(1 for s in sessions if s.duration_seconds is not None))
            )
            if any(s.duration_seconds is not None for s in sessions)
            else 0.0,
        }

    def _foundation_command_count(self) -> int:
        try:
            rows = _read_rows(_foundation_db_path(), "SELECT COUNT(*) AS n FROM commands")
            return int(rows[0]["n"]) if rows else 0
        except MirageDataUnavailable:
            return 0

    # ------------------------------------------------------------------ #
    # threat observations (normalized TI export objects)
    # ------------------------------------------------------------------ #

    def list_threat_observations(self, limit: int = 500) -> list[ThreatObservation]:
        """Build normalized ThreatObservations from backend data only.

        Sources: pipeline sessions (threat level), honeytoken events,
        sandbox blocks, agent fallbacks — each already carries backend
        severity. MITRE ids come from the T3-classified observations.
        """
        from dashboard.services.mitre_map import category_to_technique

        observations: list[ThreatObservation] = []
        sessions = {s.session_id: s for s in self._pipeline_sessions(limit)}
        commands_by_session = {
            sid: self._pipeline_commands(sid, 100) for sid in sessions
        }

        def _obs(session_id, timestamp, category, severity, confidence, evidence, technique_category=None):
            technique = category_to_technique(technique_category or category)
            oid = "obs_" + hashlib.sha1(
                f"{session_id}|{timestamp}|{category}|{evidence}".encode()
            ).hexdigest()[:12]
            observations.append(
                ThreatObservation(
                    observation_id=oid,
                    session_id=session_id or None,
                    timestamp=timestamp,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    technique_id=technique.technique_id if technique else None,
                    evidence=_redact(evidence, limit=160),
                    plane=PLANE_PIPELINE,
                )
            )

        # Session-level observations from T3 threat levels
        for sid, s in sessions.items():
            if s.threat_level in ("Medium", "High"):
                _obs(
                    sid, s.last_seen, "SESSION_RISK", s.severity, s.confidence,
                    f"session threat level {s.threat_level} (score {s.threat_score})",
                )

        # Event-derived observations
        for e in self.list_events(limit=limit):
            session = sessions.get(e.session_id)
            if e.event_type == "HONEYTOKEN_ACCESS":
                _obs(
                    e.session_id, e.timestamp, "HONEYTOKEN", "HIGH", 0.9,
                    f"honeytoken access: {e.details}", "HONEYTOKEN",
                )
            elif e.event_type == "SANDBOX_BLOCK":
                _obs(
                    e.session_id, e.timestamp, "DESTRUCTIVE", "HIGH", 0.9,
                    f"containment blocked command: {e.details}", "DESTRUCTIVE",
                )
            elif e.event_type == "CONTAINMENT_ACTIVATED":
                _obs(
                    e.session_id, e.timestamp, "CONTAINMENT", "HIGH", 0.9,
                    f"containment activated: {e.details}",
                )
            elif e.event_type == "AGENT_GUARDRAIL_REJECT":
                _obs(
                    e.session_id, e.timestamp, "AGENT_GUARDRAIL", "MEDIUM", 0.7,
                    f"guardrail rejected agent output: {e.details}",
                )
            elif e.event_type == "AGENT_FALLBACK":
                _obs(
                    e.session_id, e.timestamp, "AGENT_FALLBACK", "LOW", 0.4,
                    f"agent fell back to deterministic response: {e.details}",
                )

        # Command-derived RECON/SENSITIVE observations (T3-classified)
        for sid, cmds in commands_by_session.items():
            session = sessions.get(sid)
            for c in cmds:
                category = self.classify_command(c.raw_command)
                if category in ("RECON", "SENSITIVE"):
                    technique = category_to_technique(category)
                    _obs(
                        sid, c.timestamp, category,
                        "MEDIUM" if category == "RECON" else "HIGH",
                        session.confidence if session else 0.5,
                        f"command '{c.raw_command[:80]}' classified {category}",
                        category,
                    )

        observations.sort(key=lambda o: (o.timestamp or 0.0), reverse=True)
        return observations[:limit]


# Severity the T3 pipeline itself assigns to its event types (from T3's
# docs/CONTRACTS.md behaviour: HONEYTOKEN_ACCESS is its strongest signal,
# SANDBOX_BLOCK is containment enforcement). Display-only mapping of
# backend semantics — not invented severity.
_PIPELINE_EVENT_SEVERITY = {
    "HONEYTOKEN_ACCESS": "HIGH",
    "HONEYTOKEN_PLANTED": "INFO",
    "SANDBOX_BLOCK": "HIGH",
    "CONTAINMENT_ACTIVATED": "HIGH",
    "CONTAINMENT_BLOCK": "MEDIUM",
    "CONTAINMENT_SENSITIVE": "MEDIUM",
    "AGENT_DECISION": "INFO",
    "AGENT_FALLBACK": "WARNING",
    "AGENT_GUARDRAIL_REJECT": "WARNING",
    "AGENT_INPUT_FLAG": "WARNING",
}
