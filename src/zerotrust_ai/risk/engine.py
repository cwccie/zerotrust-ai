"""
Composite risk scoring engine.

Computes risk scores by combining signals from behavioral analytics,
device health, network context, and threat intelligence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class RiskScore:
    """Composite risk score with component breakdown."""
    entity_id: str
    composite_score: float  # 0.0 (safe) to 1.0 (critical)
    risk_level: str  # low, medium, high, critical
    components: dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    factors: list[str] = field(default_factory=list)


class ThreatIntel:
    """Simple threat intelligence store."""

    def __init__(self):
        self.malicious_ips: set[str] = set()
        self.compromised_credentials: set[str] = set()
        self.tor_exit_nodes: set[str] = set()

    def add_malicious_ip(self, ip: str) -> None:
        self.malicious_ips.add(ip)

    def add_compromised_credential(self, entity_id: str) -> None:
        self.compromised_credentials.add(entity_id)

    def check_ip(self, ip: str) -> float:
        if ip in self.malicious_ips:
            return 1.0
        if ip in self.tor_exit_nodes:
            return 0.7
        return 0.0

    def check_credential(self, entity_id: str) -> float:
        return 0.9 if entity_id in self.compromised_credentials else 0.0


class RiskEngine:
    """
    Calculates composite risk scores from multiple signal sources.

    Supports configurable weights and dynamic trust levels.
    """

    def __init__(
        self,
        behavior_weight: float = 0.30,
        device_weight: float = 0.20,
        network_weight: float = 0.15,
        threat_weight: float = 0.20,
        auth_weight: float = 0.15,
    ):
        self.weights = {
            "behavior": behavior_weight,
            "device": device_weight,
            "network": network_weight,
            "threat": threat_weight,
            "auth": auth_weight,
        }
        self.threat_intel = ThreatIntel()
        self.risk_history: dict[str, list[RiskScore]] = {}
        self.thresholds = {
            "low": 0.3,
            "medium": 0.5,
            "high": 0.7,
            "critical": 0.9,
        }

    def calculate(
        self,
        entity_id: str,
        behavior_score: float = 0.0,
        device_health: float = 1.0,
        network_trust: float = 0.5,
        source_ip: str = "",
        auth_strength: float = 0.5,
    ) -> RiskScore:
        """Calculate composite risk score."""
        factors = []
        components = {}

        # Behavioral risk (anomaly score is already 0-1, higher = riskier)
        components["behavior"] = behavior_score
        if behavior_score > 0.7:
            factors.append("High behavioral anomaly")

        # Device risk (invert health: healthy device = low risk)
        components["device"] = max(0.0, 1.0 - device_health)
        if device_health < 0.5:
            factors.append("Poor device health")

        # Network risk (invert trust)
        components["network"] = max(0.0, 1.0 - network_trust)
        if network_trust < 0.3:
            factors.append("Untrusted network")

        # Threat intel risk
        threat_score = 0.0
        if source_ip:
            ip_score = self.threat_intel.check_ip(source_ip)
            if ip_score > 0:
                threat_score = max(threat_score, ip_score)
                factors.append(f"Threat intel match on IP")
        cred_score = self.threat_intel.check_credential(entity_id)
        if cred_score > 0:
            threat_score = max(threat_score, cred_score)
            factors.append("Compromised credential")
        components["threat"] = threat_score

        # Auth risk (invert strength)
        components["auth"] = max(0.0, 1.0 - auth_strength)
        if auth_strength < 0.4:
            factors.append("Weak authentication")

        # Weighted composite
        composite = sum(
            components[k] * self.weights[k] for k in self.weights
        )
        composite = round(max(0.0, min(1.0, composite)), 4)

        # Determine level
        level = "low"
        for lbl in ("critical", "high", "medium", "low"):
            if composite >= self.thresholds[lbl]:
                level = lbl
                break

        result = RiskScore(
            entity_id=entity_id,
            composite_score=composite,
            risk_level=level,
            components=components,
            factors=factors,
        )

        if entity_id not in self.risk_history:
            self.risk_history[entity_id] = []
        self.risk_history[entity_id].append(result)

        return result

    def get_risk_trend(self, entity_id: str, n: int = 10) -> list[float]:
        """Get recent risk score history."""
        history = self.risk_history.get(entity_id, [])
        return [r.composite_score for r in history[-n:]]

    def batch_calculate(
        self, entities: list[dict[str, Any]]
    ) -> list[RiskScore]:
        """Calculate risk for multiple entities."""
        return [
            self.calculate(
                entity_id=e["entity_id"],
                behavior_score=e.get("behavior_score", 0.0),
                device_health=e.get("device_health", 1.0),
                network_trust=e.get("network_trust", 0.5),
                source_ip=e.get("source_ip", ""),
                auth_strength=e.get("auth_strength", 0.5),
            )
            for e in entities
        ]

    def population_risk_summary(self) -> dict[str, Any]:
        """Summarize risk across all entities."""
        if not self.risk_history:
            return {"total_entities": 0}

        latest = {}
        for eid, history in self.risk_history.items():
            if history:
                latest[eid] = history[-1].composite_score

        scores = np.array(list(latest.values()))
        level_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for eid, history in self.risk_history.items():
            if history:
                level_counts[history[-1].risk_level] = (
                    level_counts.get(history[-1].risk_level, 0) + 1
                )

        return {
            "total_entities": len(latest),
            "mean_risk": round(float(scores.mean()), 4),
            "max_risk": round(float(scores.max()), 4),
            "std_risk": round(float(scores.std()), 4),
            "level_distribution": level_counts,
        }
