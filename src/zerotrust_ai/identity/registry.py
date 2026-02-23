"""
Identity registry and correlation engine.

Central registry for user, service, and device identities.
Supports identity correlation across systems and session tracking.
"""

from __future__ import annotations

import time
from typing import Any

from .models import Identity, Device


class IdentityRegistry:
    """Central identity and device registry."""

    def __init__(self):
        self.identities: dict[str, Identity] = {}
        self.devices: dict[str, Device] = {}
        self.correlations: dict[str, set[str]] = {}  # alias -> identity_id set
        self.sessions: dict[str, dict[str, Any]] = {}

    # --- Identity management ---

    def register_identity(self, identity: Identity) -> None:
        self.identities[identity.identity_id] = identity

    def get_identity(self, identity_id: str) -> Identity | None:
        return self.identities.get(identity_id)

    def find_by_email(self, email: str) -> Identity | None:
        for ident in self.identities.values():
            if ident.email == email:
                return ident
        return None

    def find_by_role(self, role: str) -> list[Identity]:
        return [i for i in self.identities.values() if role in i.roles]

    def find_by_group(self, group: str) -> list[Identity]:
        return [i for i in self.identities.values() if group in i.groups]

    def disable_identity(self, identity_id: str) -> bool:
        ident = self.identities.get(identity_id)
        if ident:
            ident.enabled = False
            return True
        return False

    # --- Device management ---

    def register_device(self, device: Device) -> None:
        self.devices[device.device_id] = device

    def get_device(self, device_id: str) -> Device | None:
        return self.devices.get(device_id)

    def get_user_devices(self, owner_id: str) -> list[Device]:
        return [d for d in self.devices.values() if d.owner_id == owner_id]

    def non_compliant_devices(self) -> list[Device]:
        return [d for d in self.devices.values() if not d.compliant]

    # --- Identity correlation ---

    def add_correlation(self, alias: str, identity_id: str) -> None:
        """Link an alias (email, username, etc.) to an identity."""
        if alias not in self.correlations:
            self.correlations[alias] = set()
        self.correlations[alias].add(identity_id)

    def resolve_alias(self, alias: str) -> set[str]:
        """Resolve an alias to identity IDs."""
        return self.correlations.get(alias, set())

    # --- Session tracking ---

    def track_session(
        self,
        session_id: str,
        identity_id: str,
        device_id: str = "",
        source_ip: str = "",
    ) -> None:
        self.sessions[session_id] = {
            "identity_id": identity_id,
            "device_id": device_id,
            "source_ip": source_ip,
            "started": time.time(),
            "active": True,
        }
        ident = self.identities.get(identity_id)
        if ident:
            ident.last_active = time.time()

    def end_session(self, session_id: str) -> None:
        if session_id in self.sessions:
            self.sessions[session_id]["active"] = False

    def active_sessions(self, identity_id: str | None = None) -> list[dict[str, Any]]:
        results = []
        for sid, data in self.sessions.items():
            if not data["active"]:
                continue
            if identity_id and data["identity_id"] != identity_id:
                continue
            results.append({"session_id": sid, **data})
        return results

    # --- Summary ---

    def summary(self) -> dict[str, Any]:
        return {
            "total_identities": len(self.identities),
            "enabled_identities": sum(1 for i in self.identities.values() if i.enabled),
            "total_devices": len(self.devices),
            "compliant_devices": sum(1 for d in self.devices.values() if d.compliant),
            "active_sessions": sum(1 for s in self.sessions.values() if s["active"]),
            "identity_types": {
                t: sum(1 for i in self.identities.values() if i.identity_type == t)
                for t in ("user", "service", "system")
            },
        }
