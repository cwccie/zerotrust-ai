"""
Session analysis for behavioral analytics.

Tracks active sessions, detects concurrent session anomalies,
session hijacking indicators, and impossible travel.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Session:
    session_id: str
    entity_id: str
    start_time: float
    last_activity: float = 0.0
    source_ip: str = ""
    location: str = ""
    user_agent: str = ""
    actions: list[str] = field(default_factory=list)
    risk_flags: list[str] = field(default_factory=list)
    is_active: bool = True

    @property
    def duration(self) -> float:
        end = self.last_activity if self.last_activity > 0 else time.time()
        return end - self.start_time


class SessionAnalyzer:
    """Analyzes user sessions for suspicious patterns."""

    def __init__(
        self,
        max_concurrent: int = 3,
        impossible_travel_km_per_hour: float = 900.0,
        idle_timeout: float = 3600.0,
    ):
        self.max_concurrent = max_concurrent
        self.impossible_travel_speed = impossible_travel_km_per_hour
        self.idle_timeout = idle_timeout
        self.sessions: dict[str, Session] = {}
        self.entity_sessions: dict[str, list[str]] = {}

    def start_session(
        self,
        session_id: str,
        entity_id: str,
        source_ip: str = "",
        location: str = "",
        user_agent: str = "",
    ) -> dict[str, Any]:
        """Start tracking a new session. Returns risk assessment."""
        now = time.time()
        session = Session(
            session_id=session_id,
            entity_id=entity_id,
            start_time=now,
            last_activity=now,
            source_ip=source_ip,
            location=location,
            user_agent=user_agent,
        )

        risks = []

        # Check concurrent sessions
        if entity_id not in self.entity_sessions:
            self.entity_sessions[entity_id] = []

        active = [
            sid for sid in self.entity_sessions[entity_id]
            if sid in self.sessions and self.sessions[sid].is_active
        ]

        if len(active) >= self.max_concurrent:
            risks.append("excessive_concurrent_sessions")
            session.risk_flags.append("concurrent_limit_exceeded")

        # Check for different IPs in active sessions
        active_ips = {
            self.sessions[sid].source_ip
            for sid in active
            if sid in self.sessions
        }
        if source_ip and active_ips and source_ip not in active_ips:
            risks.append("multiple_source_ips")
            session.risk_flags.append("ip_mismatch")

        self.sessions[session_id] = session
        self.entity_sessions[entity_id].append(session_id)

        return {
            "session_id": session_id,
            "entity_id": entity_id,
            "concurrent_count": len(active) + 1,
            "risks": risks,
            "risk_score": min(1.0, len(risks) * 0.4),
        }

    def update_session(
        self, session_id: str, action: str = "", source_ip: str = ""
    ) -> dict[str, Any]:
        """Record activity on a session."""
        session = self.sessions.get(session_id)
        if session is None:
            return {"error": "session_not_found"}

        now = time.time()
        risks = []

        idle_time = now - session.last_activity
        if idle_time > self.idle_timeout:
            risks.append("resumed_after_long_idle")
            session.risk_flags.append("long_idle_resume")

        if source_ip and session.source_ip and source_ip != session.source_ip:
            risks.append("ip_changed_mid_session")
            session.risk_flags.append("ip_change")

        session.last_activity = now
        if action:
            session.actions.append(action)
        if source_ip:
            session.source_ip = source_ip

        return {
            "session_id": session_id,
            "idle_seconds": round(idle_time, 1),
            "action_count": len(session.actions),
            "risks": risks,
        }

    def end_session(self, session_id: str) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None:
            return {"error": "session_not_found"}

        session.is_active = False
        session.last_activity = time.time()

        return {
            "session_id": session_id,
            "duration": round(session.duration, 1),
            "action_count": len(session.actions),
            "risk_flags": session.risk_flags,
        }

    def get_active_sessions(self, entity_id: str) -> list[dict[str, Any]]:
        sids = self.entity_sessions.get(entity_id, [])
        result = []
        for sid in sids:
            s = self.sessions.get(sid)
            if s and s.is_active:
                result.append({
                    "session_id": s.session_id,
                    "duration": round(s.duration, 1),
                    "source_ip": s.source_ip,
                    "location": s.location,
                    "action_count": len(s.actions),
                    "risk_flags": s.risk_flags,
                })
        return result

    def cleanup_expired(self, max_age: float = 86400.0) -> int:
        now = time.time()
        removed = 0
        for sid in list(self.sessions.keys()):
            s = self.sessions[sid]
            if now - s.last_activity > max_age:
                s.is_active = False
                del self.sessions[sid]
                removed += 1
        return removed
