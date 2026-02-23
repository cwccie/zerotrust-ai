"""
ZeroTrust-AI Command Line Interface.

Commands: baseline, analyze, detect, policy, dashboard, demo
"""

from __future__ import annotations

import json
import random
import time

import click
import numpy as np

from .behavioral import BehavioralBaseline, AnomalyDetector, PatternAnalyzer
from .access import AccessDecisionEngine, AccessContext
from .access.context import DeviceHealth
from .risk import RiskEngine
from .policy import PolicyEngine
from .policy.models import Policy, PolicyRule, PolicyCondition, PolicyEffect
from .identity import IdentityRegistry
from .identity.models import Identity, Device
from .lateral import LateralMovementDetector
from .lateral.graph import AccessEdge


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """ZeroTrust-AI: AI-Accelerated Zero Trust Architecture Platform"""
    pass


@cli.command()
@click.option("--events", default=500, help="Number of synthetic events to generate")
@click.option("--entities", default=20, help="Number of entities")
def baseline(events: int, entities: int):
    """Learn behavioral baselines from synthetic data."""
    click.echo(f"[*] Generating {events} events for {entities} entities...")

    bl = BehavioralBaseline()
    rng = random.Random(42)
    entity_ids = [f"user-{i:03d}" for i in range(entities)]
    resources = [f"resource-{c}" for c in "abcdefghij"]
    locations = ["us-east", "us-west", "eu-west", "ap-south"]

    for _ in range(events):
        eid = rng.choice(entity_ids)
        event = {
            "hour": rng.gauss(10, 3) % 24,
            "day_of_week": rng.randint(0, 6),
            "resource": rng.choice(resources),
            "action": rng.choice(["read", "write", "execute"]),
            "session_duration": max(60, rng.gauss(3600, 1200)),
            "location": rng.choice(locations),
            "source_ip": f"10.0.{rng.randint(1,10)}.{rng.randint(1,254)}",
        }
        bl.observe(eid, event)

    click.echo(f"[+] Baselines learned for {len(bl.all_entity_ids())} entities")
    for eid in bl.all_entity_ids()[:5]:
        summary = bl.profile_summary(eid)
        click.echo(f"    {eid}: {summary['observation_count']} obs, peak_hour={summary['peak_hour']}, "
                    f"locations={summary['unique_locations']}, avg_session={summary['avg_session_duration']}s")
    if len(bl.all_entity_ids()) > 5:
        click.echo(f"    ... and {len(bl.all_entity_ids()) - 5} more")


@cli.command()
@click.option("--entity", default="user-001", help="Entity ID to analyze")
@click.option("--hour", default=3, help="Hour of access (0-23)")
@click.option("--location", default="unknown-region", help="Access location")
def analyze(entity: str, hour: int, location: str):
    """Analyze an access event for anomalies."""
    click.echo(f"[*] Building baseline and analyzing event for {entity}...")

    bl = BehavioralBaseline()
    rng = random.Random(42)
    resources = [f"resource-{c}" for c in "abcdef"]

    # Build baseline
    for _ in range(200):
        bl.observe(entity, {
            "hour": int(rng.gauss(10, 2) % 24),
            "day_of_week": rng.randint(0, 4),
            "resource": rng.choice(resources[:3]),
            "location": "us-east",
            "source_ip": "10.0.1.50",
            "session_duration": max(60, rng.gauss(3600, 600)),
        })

    detector = AnomalyDetector(baseline_engine=bl, threshold=0.6)

    # Analyze the test event
    result = detector.analyze(entity, {
        "hour": hour,
        "location": location,
        "resource": "resource-z",
        "source_ip": "203.0.113.99",
        "session_duration": 18000,
    })

    click.echo(f"\n--- Anomaly Analysis ---")
    click.echo(f"Entity:         {result.entity_id}")
    click.echo(f"Anomaly Score:  {result.anomaly_score:.4f}")
    click.echo(f"Is Anomalous:   {'YES' if result.is_anomalous else 'no'}")
    click.echo(f"\nComponent Scores:")
    for comp, score in result.component_scores.items():
        bar = "#" * int(score * 30)
        click.echo(f"  {comp:12s} {score:.4f} |{bar}")
    click.echo(f"\nDetails:")
    for comp, detail in result.details.items():
        click.echo(f"  {comp}: {json.dumps(detail)}")


@cli.command()
@click.option("--nodes", default=15, help="Number of graph nodes")
@click.option("--edges", default=40, help="Number of access edges")
def detect(nodes: int, edges: int):
    """Detect lateral movement patterns."""
    click.echo(f"[*] Building access graph ({nodes} nodes, {edges} edges)...")

    detector = LateralMovementDetector(hop_threshold=3)
    rng = random.Random(42)
    np_rng = np.random.RandomState(42)

    node_ids = [f"host-{i:02d}" for i in range(nodes)]

    # Add nodes with features (index 0 = privilege level)
    for nid in node_ids:
        features = np_rng.rand(8)
        if "00" in nid or "01" in nid:
            features[0] = 0.9  # High privilege
        elif int(nid.split("-")[1]) > nodes - 3:
            features[0] = 0.1  # Low privilege
        detector.graph.add_node(nid, "host", features)

    # Add edges
    for i in range(edges):
        src = rng.choice(node_ids)
        dst = rng.choice(node_ids)
        if src == dst:
            continue
        detector.add_access_event(AccessEdge(
            src=src, dst=dst,
            action=rng.choice(["ssh", "rdp", "smb", "api"]),
            timestamp=time.time() + i * 60,
            credential_type=rng.choice(["password", "key", "token"]),
            success=rng.random() > 0.1,
        ))

    # Add a suspicious hopping chain
    chain = [f"host-{nodes-1:02d}"] + [f"host-{i:02d}" for i in range(5)]
    for j in range(len(chain) - 1):
        detector.add_access_event(AccessEdge(
            src=chain[j], dst=chain[j+1],
            action="ssh", timestamp=time.time() + (edges + j) * 60,
            credential_type="token",
        ))

    detector.learn_baseline()
    alerts = detector.detect()

    click.echo(f"\n--- Lateral Movement Detection ---")
    click.echo(f"Total alerts: {len(alerts)}")
    for alert in alerts[:10]:
        sev_bar = "#" * int(alert.severity * 20)
        click.echo(f"\n  [{alert.alert_type}] severity={alert.severity:.4f} |{sev_bar}")
        click.echo(f"  Path: {' -> '.join(alert.path[:6])}")
        for k, v in alert.details.items():
            click.echo(f"    {k}: {v}")


@cli.command()
@click.option("--file", "policy_file", default=None, help="YAML policy file")
def policy(policy_file: str):
    """Manage and simulate policies."""
    engine = PolicyEngine()

    if policy_file:
        with open(policy_file) as f:
            policies = engine.load_yaml(f.read())
        click.echo(f"[+] Loaded {len(policies)} policies from {policy_file}")
    else:
        # Create demo policies
        from .policy.models import Policy, PolicyRule, PolicyCondition, PolicyEffect

        p1 = Policy(
            policy_id="deny-high-risk",
            name="Deny High Risk Access",
            rules=[PolicyRule(
                rule_id="r1",
                description="Deny when risk score exceeds threshold",
                effect=PolicyEffect.DENY,
                conditions=[PolicyCondition("risk_score", "gt", 0.8)],
                priority=10,
            )],
        )
        p2 = Policy(
            policy_id="require-mfa-external",
            name="Require MFA for External Access",
            rules=[PolicyRule(
                rule_id="r2",
                description="Challenge external access without MFA",
                effect=PolicyEffect.CHALLENGE,
                conditions=[
                    PolicyCondition("network_zone", "eq", "external"),
                    PolicyCondition("mfa_verified", "eq", False),
                ],
                priority=20,
            )],
        )
        p3 = Policy(
            policy_id="allow-internal-read",
            name="Allow Internal Read Access",
            rules=[PolicyRule(
                rule_id="r3",
                description="Allow read access from internal network",
                effect=PolicyEffect.ALLOW,
                conditions=[
                    PolicyCondition("network_zone", "eq", "internal"),
                    PolicyCondition("action", "eq", "read"),
                ],
                priority=50,
            )],
        )
        engine.add_policy(p1)
        engine.add_policy(p2)
        engine.add_policy(p3)
        click.echo("[+] Created 3 demo policies")

    # Show policies
    summary = engine.policy_summary()
    click.echo(f"\n--- Policy Summary ---")
    click.echo(f"Total: {summary['total_policies']}, Active: {summary['enabled_policies']}, Rules: {summary['total_rules']}")

    # Detect conflicts
    conflicts = engine.detect_conflicts()
    click.echo(f"\nConflicts detected: {len(conflicts)}")
    for c in conflicts:
        click.echo(f"  {c['rule_1']['rule_id']} ({c['rule_1']['effect']}) vs "
                    f"{c['rule_2']['rule_id']} ({c['rule_2']['effect']}) - winner: {c['winner']}")

    # Simulate
    test_contexts = [
        {"risk_score": 0.9, "network_zone": "external", "mfa_verified": False, "action": "write"},
        {"risk_score": 0.2, "network_zone": "internal", "mfa_verified": True, "action": "read"},
        {"risk_score": 0.5, "network_zone": "external", "mfa_verified": False, "action": "read"},
    ]
    click.echo(f"\n--- Policy Simulation ---")
    for ctx in test_contexts:
        result = engine.evaluate(ctx)
        click.echo(f"  Context: {json.dumps(ctx)}")
        click.echo(f"  Decision: {result['decision']} (rule: {result.get('rule_id', 'N/A')})")
        click.echo()

    # Export YAML
    click.echo("--- Exported YAML ---")
    click.echo(engine.export_yaml())


@cli.command()
@click.option("--host", default="127.0.0.1", help="Dashboard host")
@click.option("--port", default=5000, help="Dashboard port")
def dashboard(host: str, port: int):
    """Launch the web dashboard."""
    from .dashboard import create_dashboard

    click.echo(f"[*] Starting ZeroTrust-AI dashboard on {host}:{port}")
    app = create_dashboard(host=host, port=port)
    app.run(host=host, port=port, debug=True)


@cli.command()
def demo():
    """Run a complete zero trust demo scenario."""
    click.echo("=" * 60)
    click.echo("  ZeroTrust-AI  -  Complete Demo Scenario")
    click.echo("=" * 60)

    rng = random.Random(42)

    # 1. Identity Setup
    click.echo("\n[1/6] Setting up identities...")
    registry = IdentityRegistry()
    users = [
        Identity("alice", "Alice Chen", "user", "alice@corp.io", "engineering", ["developer"], ["eng-team"]),
        Identity("bob", "Bob Martinez", "user", "bob@corp.io", "finance", ["analyst"], ["fin-team"]),
        Identity("charlie", "Charlie Kim", "user", "charlie@corp.io", "security", ["admin", "soc-analyst"], ["sec-team"]),
        Identity("svc-api", "API Service", "service", roles=["service-account"]),
    ]
    for u in users:
        registry.register_identity(u)
    click.echo(f"    Registered {len(users)} identities")

    # 2. Behavioral Baselines
    click.echo("\n[2/6] Learning behavioral baselines...")
    bl = BehavioralBaseline()
    for user in ["alice", "bob", "charlie"]:
        for _ in range(150):
            bl.observe(user, {
                "hour": int(rng.gauss(10, 2) % 24),
                "day_of_week": rng.randint(0, 4),
                "resource": rng.choice(["db-prod", "api-internal", "docs"]),
                "location": "us-east",
                "source_ip": f"10.0.1.{rng.randint(10, 50)}",
                "session_duration": max(60, rng.gauss(3600, 800)),
            })
    click.echo(f"    Baselines for {len(bl.all_entity_ids())} users")

    # 3. Anomaly Detection
    click.echo("\n[3/6] Running anomaly detection...")
    detector = AnomalyDetector(baseline_engine=bl)

    normal = detector.analyze("alice", {"hour": 10, "resource": "db-prod", "location": "us-east", "source_ip": "10.0.1.25"})
    suspicious = detector.analyze("bob", {"hour": 3, "resource": "db-secret", "location": "cn-north", "source_ip": "203.0.113.1", "session_duration": 28800})

    click.echo(f"    Alice (normal):     score={normal.anomaly_score:.4f}, anomalous={normal.is_anomalous}")
    click.echo(f"    Bob (suspicious):   score={suspicious.anomaly_score:.4f}, anomalous={suspicious.is_anomalous}")

    # 4. Risk Scoring
    click.echo("\n[4/6] Computing risk scores...")
    risk = RiskEngine()
    risk.threat_intel.add_malicious_ip("203.0.113.1")

    r_alice = risk.calculate("alice", behavior_score=normal.anomaly_score, device_health=0.95, network_trust=0.7)
    r_bob = risk.calculate("bob", behavior_score=suspicious.anomaly_score, device_health=0.4, network_trust=0.2, source_ip="203.0.113.1")

    click.echo(f"    Alice: risk={r_alice.composite_score:.4f} ({r_alice.risk_level})")
    click.echo(f"    Bob:   risk={r_bob.composite_score:.4f} ({r_bob.risk_level}) factors={r_bob.factors}")

    # 5. Access Decisions
    click.echo("\n[5/6] Making access decisions...")
    access_eng = AccessDecisionEngine()
    access_eng.set_resource_sensitivity("db-prod", 0.8)

    d_alice = access_eng.evaluate(AccessContext(
        entity_id="alice", resource="db-prod", action="read",
        behavior_score=normal.anomaly_score, risk_score=r_alice.composite_score,
        network_zone="internal", mfa_verified=True, authentication_method="certificate",
        device=DeviceHealth(compliance_score=0.95),
    ))
    d_bob = access_eng.evaluate(AccessContext(
        entity_id="bob", resource="db-prod", action="write",
        behavior_score=suspicious.anomaly_score, risk_score=r_bob.composite_score,
        network_zone="external", mfa_verified=False, authentication_method="password",
        device=DeviceHealth(compliance_score=0.4, os_patched=False, antivirus_active=False),
    ))

    click.echo(f"    Alice -> db-prod (read):  {d_alice.decision.value} (risk={d_alice.risk_level:.4f})")
    click.echo(f"    Bob -> db-prod (write):   {d_bob.decision.value} (risk={d_bob.risk_level:.4f})")
    click.echo(f"      Reasons: {'; '.join(d_bob.reasons)}")

    # 6. Lateral Movement
    click.echo("\n[6/6] Checking lateral movement...")
    lat = LateralMovementDetector(hop_threshold=3)
    np_rng = np.random.RandomState(42)
    for h in [f"host-{i:02d}" for i in range(8)]:
        feats = np_rng.rand(8)
        if h in ("host-00", "host-01"):
            feats[0] = 0.9
        lat.graph.add_node(h, "host", feats)

    # Normal traffic
    for _ in range(30):
        lat.add_access_event(AccessEdge(
            src=f"host-{rng.randint(2,5):02d}", dst=f"host-{rng.randint(2,5):02d}",
            action="api", timestamp=time.time(),
        ))

    # Suspicious chain
    for i in range(5):
        lat.add_access_event(AccessEdge(
            src=f"host-{6+i:02d}" if i < 2 else f"host-{i:02d}",
            dst=f"host-{i:02d}",
            action="ssh", timestamp=time.time() + i * 30,
            credential_type="token",
        ))

    lat.learn_baseline()
    alerts = lat.detect()
    click.echo(f"    Alerts: {len(alerts)}")
    for a in alerts[:3]:
        click.echo(f"      [{a.alert_type}] severity={a.severity:.2f} path={' -> '.join(a.path[:5])}")

    click.echo("\n" + "=" * 60)
    click.echo("  Demo complete. Zero trust is not a product - it is a strategy.")
    click.echo("=" * 60)


def main():
    cli()


if __name__ == "__main__":
    main()
