"""
Flask web dashboard for ZeroTrust-AI.

Provides visualizations for trust scores, access decisions,
lateral movement, policy coverage, and risk timelines.
"""

from __future__ import annotations

import json
import time
from typing import Any

from flask import Flask, render_template, jsonify

from ..behavioral import BehavioralBaseline, AnomalyDetector
from ..access import AccessDecisionEngine
from ..risk import RiskEngine
from ..lateral import LateralMovementDetector
from ..policy import PolicyEngine
from ..identity import IdentityRegistry


def create_dashboard(
    baseline: BehavioralBaseline | None = None,
    risk_engine: RiskEngine | None = None,
    policy_engine: PolicyEngine | None = None,
    identity_registry: IdentityRegistry | None = None,
    access_engine: AccessDecisionEngine | None = None,
    lateral_detector: LateralMovementDetector | None = None,
    host: str = "0.0.0.0",
    port: int = 5000,
) -> Flask:
    """Create the dashboard Flask application."""

    import os
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")

    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
    )

    bl = baseline or BehavioralBaseline()
    risk = risk_engine or RiskEngine()
    policy = policy_engine or PolicyEngine()
    identity = identity_registry or IdentityRegistry()
    access = access_engine or AccessDecisionEngine()
    lateral = lateral_detector or LateralMovementDetector()
    anomaly = AnomalyDetector(baseline_engine=bl)

    @app.route("/")
    def index():
        return render_template(
            "dashboard.html",
            identity_summary=identity.summary(),
            risk_summary=risk.population_risk_summary(),
            policy_summary=policy.policy_summary(),
            decision_stats=access.decision_stats(),
        )

    @app.route("/api/dashboard/trust-heatmap")
    def trust_heatmap():
        """Trust score heatmap data."""
        data = []
        for eid in bl.all_entity_ids():
            profile = bl.get_profile(eid)
            if profile:
                result = anomaly.analyze(eid, {"hour": 12})
                data.append({
                    "entity_id": eid,
                    "trust_score": round(1.0 - result.anomaly_score, 4),
                    "observation_count": profile.observation_count,
                })
        return jsonify(data)

    @app.route("/api/dashboard/risk-timeline")
    def risk_timeline():
        """Risk score timeline data."""
        data = {}
        for eid, history in risk.risk_history.items():
            data[eid] = [
                {"score": r.composite_score, "level": r.risk_level, "time": r.timestamp}
                for r in history[-20:]
            ]
        return jsonify(data)

    @app.route("/api/dashboard/lateral-graph")
    def lateral_graph():
        """Lateral movement graph data for visualization."""
        nodes = []
        for nid, ntype in lateral.graph.node_types.items():
            nodes.append({"id": nid, "type": ntype})

        edges = []
        for edge in lateral.graph.edges[-200:]:
            edges.append({
                "source": edge.src,
                "target": edge.dst,
                "action": edge.action,
                "success": edge.success,
            })

        alerts = lateral.detect()
        return jsonify({
            "nodes": nodes,
            "edges": edges,
            "alerts": [
                {"type": a.alert_type, "severity": a.severity, "path": a.path}
                for a in alerts[:10]
            ],
        })

    @app.route("/api/dashboard/decisions")
    def decisions_log():
        return jsonify(access.recent_decisions(100))

    @app.route("/api/dashboard/policy-coverage")
    def policy_coverage():
        return jsonify(policy.policy_summary())

    return app
