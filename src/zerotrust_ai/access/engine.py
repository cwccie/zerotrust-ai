"""
Adaptive access decision engine.

Makes risk-based access decisions using context signals.
Implements never-trust-always-verify with continuous evaluation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .context import AccessContext


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Step-up authentication required
    RESTRICT = "restrict"  # Allow with reduced privileges


@dataclass
class AccessDecision:
    decision: Decision
    confidence: float
    risk_level: float
    reasons: list[str] = field(default_factory=list)
    required_actions: list[str] = field(default_factory=list)
    context_summary: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class AccessDecisionEngine:
    """
    Risk-based adaptive access control engine.

    Combines multiple context signals into a trust score and makes
    access decisions with configurable thresholds.
    """

    def __init__(
        self,
        deny_threshold: float = 0.3,
        challenge_threshold: float = 0.5,
        restrict_threshold: float = 0.7,
    ):
        self.deny_threshold = deny_threshold
        self.challenge_threshold = challenge_threshold
        self.restrict_threshold = restrict_threshold
        self.decision_log: list[AccessDecision] = []

        # Resource sensitivity levels
        self.resource_sensitivity: dict[str, float] = {}

    def set_resource_sensitivity(self, resource: str, level: float) -> None:
        """Set sensitivity level for a resource (0.0=public, 1.0=critical)."""
        self.resource_sensitivity[resource] = max(0.0, min(1.0, level))

    def evaluate(self, context: AccessContext) -> AccessDecision:
        """Evaluate an access request and return a decision."""
        trust_score = self._calculate_trust_score(context)
        sensitivity = self.resource_sensitivity.get(context.resource, 0.5)

        # Adjusted threshold based on resource sensitivity
        effective_deny = self.deny_threshold * (1 + sensitivity * 0.5)
        effective_challenge = self.challenge_threshold * (1 + sensitivity * 0.3)
        effective_restrict = self.restrict_threshold * (1 + sensitivity * 0.2)

        reasons = []
        required_actions = []

        if trust_score < effective_deny:
            decision = Decision.DENY
            reasons.append(f"Trust score {trust_score:.2f} below deny threshold {effective_deny:.2f}")
            if context.behavior_score > 0.7:
                reasons.append("High behavioral anomaly score")
            if context.device.health_score < 0.5:
                reasons.append("Device health below minimum")
        elif trust_score < effective_challenge:
            decision = Decision.CHALLENGE
            reasons.append(f"Trust score {trust_score:.2f} requires step-up auth")
            if not context.mfa_verified:
                required_actions.append("mfa_verification")
            if context.device.health_score < 0.7:
                required_actions.append("device_compliance_check")
        elif trust_score < effective_restrict:
            decision = Decision.RESTRICT
            reasons.append(f"Trust score {trust_score:.2f} allows restricted access")
            if context.action in ("write", "delete", "admin"):
                required_actions.append("reduce_to_read_only")
        else:
            decision = Decision.ALLOW
            reasons.append(f"Trust score {trust_score:.2f} meets threshold")

        result = AccessDecision(
            decision=decision,
            confidence=min(1.0, abs(trust_score - 0.5) * 2),
            risk_level=round(1.0 - trust_score, 4),
            reasons=reasons,
            required_actions=required_actions,
            context_summary=context.to_dict(),
        )

        self.decision_log.append(result)
        return result

    def _calculate_trust_score(self, ctx: AccessContext) -> float:
        """Calculate composite trust score from context signals."""
        weights = {
            "auth": 0.20,
            "device": 0.20,
            "behavior": 0.25,
            "network": 0.15,
            "risk": 0.20,
        }

        scores = {
            "auth": ctx.auth_strength,
            "device": ctx.device.health_score,
            "behavior": max(0.0, 1.0 - ctx.behavior_score),
            "network": ctx.network_trust,
            "risk": max(0.0, 1.0 - ctx.risk_score),
        }

        trust = sum(scores[k] * weights[k] for k in weights)
        return round(max(0.0, min(1.0, trust)), 4)

    def recent_decisions(self, n: int = 50) -> list[dict[str, Any]]:
        return [
            {
                "decision": d.decision.value,
                "confidence": d.confidence,
                "risk_level": d.risk_level,
                "reasons": d.reasons,
                "entity_id": d.context_summary.get("entity_id", ""),
                "resource": d.context_summary.get("resource", ""),
            }
            for d in self.decision_log[-n:]
        ]

    def decision_stats(self) -> dict[str, int]:
        stats: dict[str, int] = {"allow": 0, "deny": 0, "challenge": 0, "restrict": 0}
        for d in self.decision_log:
            stats[d.decision.value] = stats.get(d.decision.value, 0) + 1
        return stats
