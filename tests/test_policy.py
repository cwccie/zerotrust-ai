"""Tests for policy engine."""

import pytest

from zerotrust_ai.policy import PolicyEngine
from zerotrust_ai.policy.models import Policy, PolicyRule, PolicyCondition, PolicyEffect


class TestPolicyCondition:
    def test_eq(self):
        c = PolicyCondition("zone", "eq", "internal")
        assert c.evaluate({"zone": "internal"})
        assert not c.evaluate({"zone": "external"})

    def test_gt(self):
        c = PolicyCondition("risk", "gt", 0.5)
        assert c.evaluate({"risk": 0.8})
        assert not c.evaluate({"risk": 0.3})

    def test_lt(self):
        c = PolicyCondition("risk", "lt", 0.5)
        assert c.evaluate({"risk": 0.3})

    def test_in(self):
        c = PolicyCondition("action", "in", ["read", "write"])
        assert c.evaluate({"action": "read"})
        assert not c.evaluate({"action": "delete"})

    def test_missing_field(self):
        c = PolicyCondition("zone", "eq", "internal")
        assert not c.evaluate({})


class TestPolicyRule:
    def test_evaluate_all_conditions(self):
        rule = PolicyRule(
            rule_id="r1", effect=PolicyEffect.ALLOW,
            conditions=[
                PolicyCondition("zone", "eq", "internal"),
                PolicyCondition("risk", "lt", 0.5),
            ],
        )
        assert rule.evaluate({"zone": "internal", "risk": 0.2})
        assert not rule.evaluate({"zone": "internal", "risk": 0.8})

    def test_disabled_rule(self):
        rule = PolicyRule(rule_id="r1", enabled=False,
                         conditions=[PolicyCondition("x", "eq", 1)])
        assert not rule.evaluate({"x": 1})


class TestPolicyEngine:
    def test_evaluate_deny(self, policy_engine):
        result = policy_engine.evaluate({"risk_score": 0.9})
        assert result["decision"] == "deny"

    def test_evaluate_allow(self, policy_engine):
        result = policy_engine.evaluate({"network_zone": "internal", "action": "read"})
        assert result["decision"] == "allow"

    def test_default_deny(self, policy_engine):
        result = policy_engine.evaluate({"network_zone": "external", "action": "write"})
        assert result["decision"] == "deny"
        assert result.get("default_deny", False)

    def test_priority_ordering(self):
        engine = PolicyEngine()
        engine.add_policy(Policy(
            policy_id="p1", name="Low Priority Allow",
            rules=[PolicyRule(rule_id="r1", effect=PolicyEffect.ALLOW,
                             conditions=[PolicyCondition("x", "eq", 1)], priority=100)],
        ))
        engine.add_policy(Policy(
            policy_id="p2", name="High Priority Deny",
            rules=[PolicyRule(rule_id="r2", effect=PolicyEffect.DENY,
                             conditions=[PolicyCondition("x", "eq", 1)], priority=10)],
        ))
        result = engine.evaluate({"x": 1})
        assert result["decision"] == "deny"

    def test_detect_conflicts(self):
        engine = PolicyEngine()
        engine.add_policy(Policy(
            policy_id="p1", name="Allow",
            rules=[PolicyRule(rule_id="r1", effect=PolicyEffect.ALLOW,
                             conditions=[PolicyCondition("zone", "eq", "internal")], priority=50)],
        ))
        engine.add_policy(Policy(
            policy_id="p2", name="Deny",
            rules=[PolicyRule(rule_id="r2", effect=PolicyEffect.DENY,
                             conditions=[PolicyCondition("zone", "eq", "internal")], priority=10)],
        ))
        conflicts = engine.detect_conflicts()
        assert len(conflicts) > 0

    def test_simulate(self, policy_engine):
        contexts = [
            {"risk_score": 0.9},
            {"network_zone": "internal", "action": "read"},
        ]
        results = policy_engine.simulate(contexts)
        assert len(results) == 2
        assert results[0]["decision"] == "deny"
        assert results[1]["decision"] == "allow"

    def test_yaml_roundtrip(self, policy_engine):
        yaml_str = policy_engine.export_yaml()
        assert "deny-high-risk" in yaml_str

        new_engine = PolicyEngine()
        policies = new_engine.load_yaml(yaml_str)
        assert len(policies) == 2

    def test_remove_policy(self, policy_engine):
        assert policy_engine.remove_policy("deny-high-risk")
        assert not policy_engine.remove_policy("nonexistent")

    def test_policy_summary(self, policy_engine):
        summary = policy_engine.policy_summary()
        assert summary["total_policies"] == 2
        assert summary["total_rules"] == 2

    def test_least_privilege_recommendations(self, policy_engine):
        log = [
            {"entity_id": "alice", "resource": "db", "action": "read"},
            {"entity_id": "alice", "resource": "api", "action": "read"},
            {"entity_id": "bob", "resource": "db", "action": "write"},
        ]
        recs = policy_engine.least_privilege_recommendations(log)
        assert len(recs) == 2

    def test_from_dict_roundtrip(self):
        p = Policy(
            policy_id="test", name="Test",
            rules=[PolicyRule(
                rule_id="r1", effect=PolicyEffect.ALLOW,
                conditions=[PolicyCondition("x", "eq", 1)],
            )],
        )
        d = p.to_dict()
        p2 = Policy.from_dict(d)
        assert p2.policy_id == "test"
        assert len(p2.rules) == 1
