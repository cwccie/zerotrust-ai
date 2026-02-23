"""
Access context for adaptive access control.

Captures all contextual signals used to make access decisions:
device health, location, time, behavior score, network posture.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceHealth:
    """Device security posture assessment."""
    device_id: str = ""
    os_patched: bool = True
    antivirus_active: bool = True
    disk_encrypted: bool = True
    firewall_enabled: bool = True
    compliance_score: float = 1.0  # 0.0-1.0
    last_check: float = field(default_factory=time.time)

    @property
    def health_score(self) -> float:
        checks = [
            self.os_patched,
            self.antivirus_active,
            self.disk_encrypted,
            self.firewall_enabled,
        ]
        binary_score = sum(checks) / len(checks)
        return round(binary_score * 0.6 + self.compliance_score * 0.4, 4)


@dataclass
class AccessContext:
    """Complete context for an access decision."""
    entity_id: str
    resource: str
    action: str = "read"
    source_ip: str = ""
    location: str = ""
    hour: int = -1
    day_of_week: int = -1
    device: DeviceHealth = field(default_factory=DeviceHealth)
    behavior_score: float = 0.0  # From anomaly detector, 0=normal
    risk_score: float = 0.0  # From risk engine
    session_id: str = ""
    authentication_method: str = "password"
    mfa_verified: bool = False
    network_zone: str = "external"  # internal, dmz, external
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def auth_strength(self) -> float:
        """Authentication strength score 0.0-1.0."""
        base = {
            "certificate": 0.9,
            "hardware_token": 0.85,
            "biometric": 0.8,
            "totp": 0.7,
            "password": 0.4,
            "api_key": 0.5,
            "session_cookie": 0.3,
        }.get(self.authentication_method, 0.3)
        if self.mfa_verified:
            base = min(1.0, base + 0.2)
        return base

    @property
    def network_trust(self) -> float:
        """Network zone trust level 0.0-1.0."""
        return {
            "internal": 0.7,
            "vpn": 0.6,
            "dmz": 0.4,
            "external": 0.2,
        }.get(self.network_zone, 0.1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "resource": self.resource,
            "action": self.action,
            "source_ip": self.source_ip,
            "location": self.location,
            "device_health": self.device.health_score,
            "behavior_score": self.behavior_score,
            "risk_score": self.risk_score,
            "auth_strength": self.auth_strength,
            "network_trust": self.network_trust,
            "mfa_verified": self.mfa_verified,
        }
