"""
Policy evaluation engine.

Evaluates access requests against YAML-defined policies,
detects conflicts, and recommends least-privilege rules.
"""

from __future__ import annotations

import yaml
from typing import Any

from .models import Policy, PolicyRule, PolicyCondition, PolicyEffect


class PolicyEngine:
    """Evaluates policies and manages the policy store."""

    def __init__(self):
        self.policies: dict[str, Policy] = {}

    def add_policy(self, policy: Policy) -> None:
        self.policies[policy.policy_id] = policy

    def remove_policy(self, policy_id: str) -> bool:
        return self.policies.pop(policy_id, None) is not None

    def evaluate(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate all policies against a context.
        Returns the highest-priority matching rule's effect.
        """
        matches: list[tuple[int, PolicyRule, str]] = []

        for policy in self.policies.values():
            if not policy.enabled:
                continue
            for rule in policy.rules:
                if rule.evaluate(context):
                    matches.append((rule.priority, rule, policy.policy_id))

        if not matches:
            return {
                "decision": "deny",
                "reason": "no_matching_policy",
                "default_deny": True,
            }

        # Sort by priority (lowest number = highest priority)
        matches.sort(key=lambda x: x[0])
        best = matches[0]

        return {
            "decision": best[1].effect.value,
            "rule_id": best[1].rule_id,
            "policy_id": best[2],
            "priority": best[0],
            "description": best[1].description,
            "total_matches": len(matches),
        }

    def simulate(
        self, contexts: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Simulate policy evaluation across multiple contexts (what-if)."""
        return [self.evaluate(ctx) for ctx in contexts]

    def detect_conflicts(self) -> list[dict[str, Any]]:
        """Detect conflicting rules across policies."""
        conflicts = []
        all_rules: list[tuple[str, PolicyRule]] = []

        for policy in self.policies.values():
            if not policy.enabled:
                continue
            for rule in policy.rules:
                if rule.enabled:
                    all_rules.append((policy.policy_id, rule))

        # Compare each pair
        for i in range(len(all_rules)):
            for j in range(i + 1, len(all_rules)):
                pid1, r1 = all_rules[i]
                pid2, r2 = all_rules[j]

                if r1.effect == r2.effect:
                    continue  # Same effect = no conflict

                # Check if conditions overlap
                if self._conditions_overlap(r1.conditions, r2.conditions):
                    conflicts.append({
                        "rule_1": {"policy_id": pid1, "rule_id": r1.rule_id, "effect": r1.effect.value},
                        "rule_2": {"policy_id": pid2, "rule_id": r2.rule_id, "effect": r2.effect.value},
                        "type": "overlapping_conditions_different_effects",
                        "resolved_by": "priority",
                        "winner": r1.rule_id if r1.priority <= r2.priority else r2.rule_id,
                    })

        return conflicts

    def _conditions_overlap(
        self, conds1: list[PolicyCondition], conds2: list[PolicyCondition]
    ) -> bool:
        """Check if two condition sets could match the same context."""
        fields1 = {c.field for c in conds1}
        fields2 = {c.field for c in conds2}
        shared = fields1 & fields2

        if not shared:
            return True  # No shared fields means they could overlap

        for field in shared:
            c1 = [c for c in conds1 if c.field == field]
            c2 = [c for c in conds2 if c.field == field]
            for a in c1:
                for b in c2:
                    if a.operator == "eq" and b.operator == "eq" and a.value != b.value:
                        return False

        return True

    def load_yaml(self, yaml_str: str) -> list[Policy]:
        """Load policies from YAML string."""
        data = yaml.safe_load(yaml_str)
        policies = []

        for pdata in data.get("policies", [data] if "policy_id" in data else []):
            policy = Policy.from_dict(pdata)
            self.add_policy(policy)
            policies.append(policy)

        return policies

    def export_yaml(self) -> str:
        """Export all policies to YAML."""
        data = {"policies": [p.to_dict() for p in self.policies.values()]}
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    def least_privilege_recommendations(
        self, access_log: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Recommend least-privilege policies based on actual access patterns."""
        # Track what resources each entity actually accesses
        entity_resources: dict[str, set[str]] = {}
        entity_actions: dict[str, set[str]] = {}

        for entry in access_log:
            eid = entry.get("entity_id", "")
            resource = entry.get("resource", "")
            action = entry.get("action", "read")
            if eid and resource:
                if eid not in entity_resources:
                    entity_resources[eid] = set()
                    entity_actions[eid] = set()
                entity_resources[eid].add(resource)
                entity_actions[eid].add(action)

        recommendations = []
        for eid in entity_resources:
            recommendations.append({
                "entity_id": eid,
                "recommended_resources": sorted(entity_resources[eid]),
                "recommended_actions": sorted(entity_actions[eid]),
                "principle": "least_privilege",
                "note": f"Entity accessed {len(entity_resources[eid])} resources with {len(entity_actions[eid])} action types",
            })

        return recommendations

    def policy_summary(self) -> dict[str, Any]:
        return {
            "total_policies": len(self.policies),
            "enabled_policies": sum(1 for p in self.policies.values() if p.enabled),
            "total_rules": sum(len(p.rules) for p in self.policies.values()),
            "policies": [
                {
                    "policy_id": p.policy_id,
                    "name": p.name,
                    "enabled": p.enabled,
                    "rule_count": len(p.rules),
                }
                for p in self.policies.values()
            ],
        }
