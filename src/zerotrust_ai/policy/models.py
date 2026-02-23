"""
Policy data models.

YAML-compatible policy definitions for zero trust access control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"


@dataclass
class PolicyCondition:
    """A condition that must be met for a rule to apply."""
    field: str  # e.g., "risk_score", "location", "hour"
    operator: str  # eq, ne, gt, lt, gte, lte, in, not_in
    value: Any

    def evaluate(self, context: dict[str, Any]) -> bool:
        actual = context.get(self.field)
        if actual is None:
            return False

        ops = {
            "eq": lambda a, v: a == v,
            "ne": lambda a, v: a != v,
            "gt": lambda a, v: a > v,
            "lt": lambda a, v: a < v,
            "gte": lambda a, v: a >= v,
            "lte": lambda a, v: a <= v,
            "in": lambda a, v: a in v,
            "not_in": lambda a, v: a not in v,
        }
        op_fn = ops.get(self.operator)
        if op_fn is None:
            return False
        try:
            return op_fn(actual, self.value)
        except (TypeError, ValueError):
            return False


@dataclass
class PolicyRule:
    """A single rule within a policy."""
    rule_id: str
    description: str = ""
    effect: PolicyEffect = PolicyEffect.DENY
    conditions: list[PolicyCondition] = field(default_factory=list)
    priority: int = 100  # Lower = higher priority
    enabled: bool = True

    def evaluate(self, context: dict[str, Any]) -> bool:
        """Return True if all conditions match."""
        if not self.enabled:
            return False
        return all(c.evaluate(context) for c in self.conditions)


@dataclass
class Policy:
    """A named policy containing rules."""
    policy_id: str
    name: str
    description: str = ""
    rules: list[PolicyRule] = field(default_factory=list)
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "tags": self.tags,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "description": r.description,
                    "effect": r.effect.value,
                    "priority": r.priority,
                    "enabled": r.enabled,
                    "conditions": [
                        {"field": c.field, "operator": c.operator, "value": c.value}
                        for c in r.conditions
                    ],
                }
                for r in self.rules
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        rules = []
        for rd in data.get("rules", []):
            conditions = [
                PolicyCondition(
                    field=cd["field"],
                    operator=cd["operator"],
                    value=cd["value"],
                )
                for cd in rd.get("conditions", [])
            ]
            rules.append(PolicyRule(
                rule_id=rd["rule_id"],
                description=rd.get("description", ""),
                effect=PolicyEffect(rd.get("effect", "deny")),
                conditions=conditions,
                priority=rd.get("priority", 100),
                enabled=rd.get("enabled", True),
            ))

        return cls(
            policy_id=data["policy_id"],
            name=data["name"],
            description=data.get("description", ""),
            rules=rules,
            enabled=data.get("enabled", True),
            tags=data.get("tags", []),
        )
