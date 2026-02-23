"""Identity and device data models."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Identity:
    """A user or service identity."""
    identity_id: str
    name: str
    identity_type: str = "user"  # user, service, system
    email: str = ""
    department: str = ""
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    enabled: bool = True
    risk_level: str = "low"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "name": self.name,
            "identity_type": self.identity_type,
            "email": self.email,
            "department": self.department,
            "roles": self.roles,
            "groups": self.groups,
            "enabled": self.enabled,
            "risk_level": self.risk_level,
        }


@dataclass
class Device:
    """A managed device."""
    device_id: str
    name: str
    device_type: str = "workstation"  # workstation, server, mobile, iot
    os: str = ""
    os_version: str = ""
    owner_id: str = ""
    managed: bool = True
    compliant: bool = True
    encrypted: bool = True
    last_seen: float = field(default_factory=time.time)
    trust_score: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "device_type": self.device_type,
            "os": self.os,
            "owner_id": self.owner_id,
            "managed": self.managed,
            "compliant": self.compliant,
            "trust_score": self.trust_score,
        }
