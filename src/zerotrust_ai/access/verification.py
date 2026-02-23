"""
Continuous verification engine.

Implements continuous verification - not just at login but throughout
the entire session lifecycle. Periodically re-evaluates trust.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .context import AccessContext
from .engine import AccessDecisionEngine, Decision


@dataclass
class VerificationState:
    entity_id: str
    session_id: str
    initial_decision: Decision = Decision.ALLOW
    current_decision: Decision = Decision.ALLOW
    last_verified: float = field(default_factory=time.time)
    verification_count: int = 0
    escalation_count: int = 0
    trust_history: list[float] = field(default_factory=list)


class ContinuousVerifier:
    """
    Continuously re-evaluates access decisions during active sessions.

    Trust is not a one-time gate - it degrades over time and must
    be re-earned through continued normal behavior.
    """

    def __init__(
        self,
        engine: AccessDecisionEngine | None = None,
        reverify_interval: float = 300.0,
        trust_decay_rate: float = 0.01,
    ):
        self.engine = engine or AccessDecisionEngine()
        self.reverify_interval = reverify_interval
        self.trust_decay_rate = trust_decay_rate
        self.states: dict[str, VerificationState] = {}

    def initialize_session(
        self, context: AccessContext
    ) -> dict[str, Any]:
        """Initialize continuous verification for a new session."""
        decision = self.engine.evaluate(context)

        state = VerificationState(
            entity_id=context.entity_id,
            session_id=context.session_id,
            initial_decision=decision.decision,
            current_decision=decision.decision,
            trust_history=[1.0 - decision.risk_level],
        )

        key = f"{context.entity_id}:{context.session_id}"
        self.states[key] = state

        return {
            "session_id": context.session_id,
            "initial_decision": decision.decision.value,
            "risk_level": decision.risk_level,
            "next_verification": time.time() + self.reverify_interval,
        }

    def reverify(self, context: AccessContext) -> dict[str, Any]:
        """Re-evaluate trust for an active session."""
        key = f"{context.entity_id}:{context.session_id}"
        state = self.states.get(key)

        if state is None:
            return self.initialize_session(context)

        state.verification_count += 1
        state.last_verified = time.time()

        decision = self.engine.evaluate(context)
        new_trust = 1.0 - decision.risk_level
        state.trust_history.append(new_trust)

        # Detect trust degradation
        escalated = False
        if decision.decision.value < state.current_decision.value:
            state.escalation_count += 1
            escalated = True

        prev_decision = state.current_decision
        state.current_decision = decision.decision

        return {
            "session_id": context.session_id,
            "previous_decision": prev_decision.value,
            "current_decision": decision.decision.value,
            "risk_level": decision.risk_level,
            "trust_trend": self._trust_trend(state),
            "escalated": escalated,
            "verification_count": state.verification_count,
        }

    def needs_reverification(self, entity_id: str, session_id: str) -> bool:
        key = f"{entity_id}:{session_id}"
        state = self.states.get(key)
        if state is None:
            return True
        return (time.time() - state.last_verified) > self.reverify_interval

    def _trust_trend(self, state: VerificationState) -> str:
        history = state.trust_history
        if len(history) < 2:
            return "stable"
        recent = history[-3:]
        if len(recent) >= 2:
            delta = recent[-1] - recent[0]
            if delta < -0.1:
                return "degrading"
            elif delta > 0.1:
                return "improving"
        return "stable"

    def get_state(self, entity_id: str, session_id: str) -> dict[str, Any] | None:
        key = f"{entity_id}:{session_id}"
        state = self.states.get(key)
        if state is None:
            return None
        return {
            "entity_id": state.entity_id,
            "session_id": state.session_id,
            "current_decision": state.current_decision.value,
            "verification_count": state.verification_count,
            "escalation_count": state.escalation_count,
            "trust_trend": self._trust_trend(state),
        }
