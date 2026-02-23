"""Tests for adaptive access control."""

import pytest

from zerotrust_ai.access import AccessDecisionEngine, AccessContext, ContinuousVerifier
from zerotrust_ai.access.context import DeviceHealth
from zerotrust_ai.access.engine import Decision


class TestDeviceHealth:
    def test_full_health(self):
        d = DeviceHealth(compliance_score=1.0)
        assert d.health_score == 1.0

    def test_partial_health(self):
        d = DeviceHealth(os_patched=False, antivirus_active=False, compliance_score=0.5)
        assert d.health_score < 1.0
        assert d.health_score > 0.0

    def test_zero_health(self):
        d = DeviceHealth(
            os_patched=False, antivirus_active=False,
            disk_encrypted=False, firewall_enabled=False,
            compliance_score=0.0,
        )
        assert d.health_score == 0.0


class TestAccessContext:
    def test_auth_strength_certificate(self):
        ctx = AccessContext(entity_id="u", resource="r", authentication_method="certificate")
        assert ctx.auth_strength == 0.9

    def test_auth_strength_password_mfa(self):
        ctx = AccessContext(entity_id="u", resource="r", authentication_method="password", mfa_verified=True)
        assert abs(ctx.auth_strength - 0.6) < 1e-10

    def test_network_trust_internal(self):
        ctx = AccessContext(entity_id="u", resource="r", network_zone="internal")
        assert ctx.network_trust == 0.7

    def test_network_trust_external(self):
        ctx = AccessContext(entity_id="u", resource="r", network_zone="external")
        assert ctx.network_trust == 0.2

    def test_to_dict(self):
        ctx = AccessContext(entity_id="alice", resource="db-prod")
        d = ctx.to_dict()
        assert d["entity_id"] == "alice"
        assert d["resource"] == "db-prod"


class TestAccessDecisionEngine:
    def test_allow_high_trust(self):
        engine = AccessDecisionEngine()
        ctx = AccessContext(
            entity_id="alice", resource="docs", action="read",
            behavior_score=0.1, risk_score=0.1,
            network_zone="internal", mfa_verified=True,
            authentication_method="certificate",
            device=DeviceHealth(compliance_score=1.0),
        )
        result = engine.evaluate(ctx)
        assert result.decision == Decision.ALLOW

    def test_deny_high_risk(self):
        engine = AccessDecisionEngine()
        ctx = AccessContext(
            entity_id="bob", resource="db-prod", action="delete",
            behavior_score=0.9, risk_score=0.95,
            network_zone="external", mfa_verified=False,
            authentication_method="password",
            device=DeviceHealth(compliance_score=0.1, os_patched=False, antivirus_active=False),
        )
        result = engine.evaluate(ctx)
        assert result.decision in (Decision.DENY, Decision.CHALLENGE)
        assert result.risk_level > 0.5

    def test_resource_sensitivity(self):
        engine = AccessDecisionEngine()
        engine.set_resource_sensitivity("vault", 1.0)
        ctx = AccessContext(
            entity_id="u", resource="vault",
            behavior_score=0.4, risk_score=0.4,
            network_zone="external",
            authentication_method="password",
        )
        result = engine.evaluate(ctx)
        # High sensitivity should make thresholds stricter
        assert result.risk_level > 0.3

    def test_decision_log(self):
        engine = AccessDecisionEngine()
        ctx = AccessContext(entity_id="u", resource="r")
        engine.evaluate(ctx)
        engine.evaluate(ctx)
        assert len(engine.decision_log) == 2

    def test_recent_decisions(self):
        engine = AccessDecisionEngine()
        for i in range(5):
            engine.evaluate(AccessContext(entity_id=f"u{i}", resource="r"))
        recent = engine.recent_decisions(3)
        assert len(recent) == 3

    def test_decision_stats(self):
        engine = AccessDecisionEngine()
        engine.evaluate(AccessContext(
            entity_id="u", resource="r", network_zone="internal",
            authentication_method="certificate", mfa_verified=True,
            device=DeviceHealth(compliance_score=1.0),
        ))
        stats = engine.decision_stats()
        assert sum(stats.values()) == 1


class TestContinuousVerifier:
    def test_initialize_session(self):
        verifier = ContinuousVerifier()
        ctx = AccessContext(
            entity_id="alice", resource="docs", session_id="s1",
            network_zone="internal", authentication_method="certificate",
            mfa_verified=True, device=DeviceHealth(compliance_score=1.0),
        )
        result = verifier.initialize_session(ctx)
        assert "session_id" in result
        assert "initial_decision" in result

    def test_reverify(self):
        verifier = ContinuousVerifier()
        ctx = AccessContext(
            entity_id="alice", resource="docs", session_id="s1",
            network_zone="internal", authentication_method="certificate",
            mfa_verified=True, device=DeviceHealth(compliance_score=1.0),
        )
        verifier.initialize_session(ctx)
        result = verifier.reverify(ctx)
        assert "current_decision" in result
        assert result["verification_count"] == 1

    def test_needs_reverification(self):
        verifier = ContinuousVerifier(reverify_interval=0.0)
        ctx = AccessContext(entity_id="alice", resource="r", session_id="s1")
        verifier.initialize_session(ctx)
        assert verifier.needs_reverification("alice", "s1")

    def test_get_state(self):
        verifier = ContinuousVerifier()
        ctx = AccessContext(entity_id="alice", resource="r", session_id="s1",
                           network_zone="internal", authentication_method="certificate")
        verifier.initialize_session(ctx)
        state = verifier.get_state("alice", "s1")
        assert state is not None
        assert state["entity_id"] == "alice"
