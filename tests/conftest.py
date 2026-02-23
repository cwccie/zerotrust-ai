"""Shared test fixtures for ZeroTrust-AI."""

import random
import time

import numpy as np
import pytest

from zerotrust_ai.behavioral import BehavioralBaseline, AnomalyDetector
from zerotrust_ai.access import AccessDecisionEngine, AccessContext
from zerotrust_ai.access.context import DeviceHealth
from zerotrust_ai.risk import RiskEngine
from zerotrust_ai.policy import PolicyEngine
from zerotrust_ai.policy.models import Policy, PolicyRule, PolicyCondition, PolicyEffect
from zerotrust_ai.identity import IdentityRegistry
from zerotrust_ai.identity.models import Identity, Device
from zerotrust_ai.lateral import LateralMovementDetector
from zerotrust_ai.lateral.graph import AccessEdge, AccessGraph
from zerotrust_ai.microseg.flows import FlowAnalyzer, Flow
from zerotrust_ai.microseg.segments import SegmentManager


@pytest.fixture
def rng():
    return random.Random(42)


@pytest.fixture
def np_rng():
    return np.random.RandomState(42)


@pytest.fixture
def baseline_engine(rng):
    bl = BehavioralBaseline()
    for uid in ["user-001", "user-002", "user-003"]:
        for _ in range(100):
            bl.observe(uid, {
                "hour": int(rng.gauss(10, 2) % 24),
                "day_of_week": rng.randint(0, 4),
                "resource": rng.choice(["db-prod", "api", "docs"]),
                "action": rng.choice(["read", "write"]),
                "location": "us-east",
                "source_ip": f"10.0.1.{rng.randint(10, 30)}",
                "session_duration": max(60, rng.gauss(3600, 600)),
            })
    return bl


@pytest.fixture
def anomaly_detector(baseline_engine):
    return AnomalyDetector(baseline_engine=baseline_engine, threshold=0.6)


@pytest.fixture
def risk_engine():
    engine = RiskEngine()
    engine.threat_intel.add_malicious_ip("198.51.100.1")
    engine.threat_intel.add_compromised_credential("compromised-user")
    return engine


@pytest.fixture
def policy_engine():
    engine = PolicyEngine()
    engine.add_policy(Policy(
        policy_id="deny-high-risk",
        name="Deny High Risk",
        rules=[PolicyRule(
            rule_id="r1", effect=PolicyEffect.DENY,
            conditions=[PolicyCondition("risk_score", "gt", 0.8)],
            priority=10,
        )],
    ))
    engine.add_policy(Policy(
        policy_id="allow-internal",
        name="Allow Internal",
        rules=[PolicyRule(
            rule_id="r2", effect=PolicyEffect.ALLOW,
            conditions=[
                PolicyCondition("network_zone", "eq", "internal"),
                PolicyCondition("action", "eq", "read"),
            ],
            priority=50,
        )],
    ))
    return engine


@pytest.fixture
def identity_registry():
    reg = IdentityRegistry()
    reg.register_identity(Identity("alice", "Alice", "user", "alice@corp.io", "engineering", ["developer"]))
    reg.register_identity(Identity("bob", "Bob", "user", "bob@corp.io", "finance", ["analyst"]))
    reg.register_identity(Identity("svc-api", "API Service", "service", roles=["service-account"]))
    reg.register_device(Device("dev-001", "Alice Laptop", "workstation", owner_id="alice"))
    reg.register_device(Device("dev-002", "Bob Desktop", "workstation", owner_id="bob", compliant=False))
    return reg


@pytest.fixture
def access_graph(np_rng):
    graph = AccessGraph()
    for i in range(6):
        feats = np_rng.rand(8)
        if i < 2:
            feats[0] = 0.9
        elif i > 3:
            feats[0] = 0.1
        graph.add_node(f"host-{i:02d}", "host", feats)

    edges = [
        ("host-04", "host-03"), ("host-03", "host-02"),
        ("host-02", "host-01"), ("host-05", "host-04"),
        ("host-03", "host-04"), ("host-02", "host-03"),
    ]
    for src, dst in edges:
        graph.add_edge(AccessEdge(src=src, dst=dst, action="ssh", timestamp=time.time()))
    return graph


@pytest.fixture
def flow_analyzer(rng):
    fa = FlowAnalyzer()
    hosts_a = [f"10.1.1.{i}" for i in range(1, 4)]
    hosts_b = [f"10.1.2.{i}" for i in range(1, 4)]
    # Intra-cluster flows
    for _ in range(20):
        fa.add_flow(Flow(src=rng.choice(hosts_a), dst=rng.choice(hosts_a), port=8080))
    for _ in range(20):
        fa.add_flow(Flow(src=rng.choice(hosts_b), dst=rng.choice(hosts_b), port=3306))
    # Cross-cluster flows
    for _ in range(5):
        fa.add_flow(Flow(src=rng.choice(hosts_a), dst=rng.choice(hosts_b), port=443))
    return fa


@pytest.fixture
def segment_manager():
    sm = SegmentManager()
    sm.create_segment("web", "Web Tier", trust_level=0.4)
    sm.create_segment("app", "App Tier", trust_level=0.6)
    sm.create_segment("data", "Data Tier", trust_level=0.9)
    sm.add_member("web", "10.1.1.1")
    sm.add_member("web", "10.1.1.2")
    sm.add_member("app", "10.1.2.1")
    sm.add_member("app", "10.1.2.2")
    sm.add_member("data", "10.1.3.1")
    sm.allow_communication("web", "app", [8080, 8443])
    sm.allow_communication("app", "data", [3306, 5432])
    return sm
