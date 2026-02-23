"""Tests for risk scoring engine."""

import pytest

from zerotrust_ai.risk import RiskEngine


class TestRiskEngine:
    def test_low_risk(self, risk_engine):
        score = risk_engine.calculate(
            "alice", behavior_score=0.1, device_health=0.95,
            network_trust=0.8, auth_strength=0.9,
        )
        assert score.composite_score < 0.3
        assert score.risk_level == "low"

    def test_high_risk(self, risk_engine):
        score = risk_engine.calculate(
            "bob", behavior_score=0.9, device_health=0.2,
            network_trust=0.1, auth_strength=0.3,
        )
        assert score.composite_score > 0.5
        assert score.risk_level in ("medium", "high", "critical")

    def test_threat_intel_ip(self, risk_engine):
        score = risk_engine.calculate(
            "charlie", source_ip="198.51.100.1", behavior_score=0.1,
        )
        assert score.composite_score > 0.1
        assert any("IP" in f for f in score.factors)

    def test_compromised_credential(self, risk_engine):
        score = risk_engine.calculate("compromised-user", behavior_score=0.1)
        assert any("Compromised" in f for f in score.factors)

    def test_risk_history(self, risk_engine):
        risk_engine.calculate("alice", behavior_score=0.1)
        risk_engine.calculate("alice", behavior_score=0.5)
        trend = risk_engine.get_risk_trend("alice")
        assert len(trend) == 2
        assert trend[1] > trend[0]

    def test_batch_calculate(self, risk_engine):
        entities = [
            {"entity_id": "a", "behavior_score": 0.1},
            {"entity_id": "b", "behavior_score": 0.9},
        ]
        results = risk_engine.batch_calculate(entities)
        assert len(results) == 2
        assert results[0].composite_score < results[1].composite_score

    def test_population_summary(self, risk_engine):
        risk_engine.calculate("a", behavior_score=0.1)
        risk_engine.calculate("b", behavior_score=0.8)
        summary = risk_engine.population_risk_summary()
        assert summary["total_entities"] == 2
        assert "mean_risk" in summary

    def test_components(self, risk_engine):
        score = risk_engine.calculate("x", behavior_score=0.5, device_health=0.8)
        assert "behavior" in score.components
        assert "device" in score.components
        assert "network" in score.components
        assert "threat" in score.components
        assert "auth" in score.components
