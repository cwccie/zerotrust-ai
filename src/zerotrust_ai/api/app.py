"""
Flask REST API for ZeroTrust-AI.

Provides endpoints for access decisions, risk queries,
policy management, and behavioral reports.
"""

from __future__ import annotations

import time
from typing import Any

from flask import Flask, jsonify, request

from ..behavioral import BehavioralBaseline, AnomalyDetector
from ..access import AccessDecisionEngine, AccessContext
from ..access.context import DeviceHealth
from ..risk import RiskEngine
from ..policy import PolicyEngine
from ..identity import IdentityRegistry
from ..lateral import LateralMovementDetector


def create_app(
    baseline: BehavioralBaseline | None = None,
    risk_engine: RiskEngine | None = None,
    policy_engine: PolicyEngine | None = None,
    identity_registry: IdentityRegistry | None = None,
    access_engine: AccessDecisionEngine | None = None,
    lateral_detector: LateralMovementDetector | None = None,
) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__)

    bl = baseline or BehavioralBaseline()
    anomaly = AnomalyDetector(baseline_engine=bl)
    risk = risk_engine or RiskEngine()
    policy = policy_engine or PolicyEngine()
    identity = identity_registry or IdentityRegistry()
    access = access_engine or AccessDecisionEngine()
    lateral = lateral_detector or LateralMovementDetector()

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "timestamp": time.time()})

    # --- Access Decisions ---

    @app.route("/api/v1/access/decide", methods=["POST"])
    def access_decide():
        data = request.get_json() or {}
        ctx = AccessContext(
            entity_id=data.get("entity_id", ""),
            resource=data.get("resource", ""),
            action=data.get("action", "read"),
            source_ip=data.get("source_ip", ""),
            location=data.get("location", ""),
            network_zone=data.get("network_zone", "external"),
            mfa_verified=data.get("mfa_verified", False),
            authentication_method=data.get("auth_method", "password"),
            behavior_score=data.get("behavior_score", 0.0),
            risk_score=data.get("risk_score", 0.0),
            device=DeviceHealth(
                compliance_score=data.get("device_compliance", 1.0),
            ),
        )
        decision = access.evaluate(ctx)
        return jsonify({
            "decision": decision.decision.value,
            "risk_level": decision.risk_level,
            "confidence": decision.confidence,
            "reasons": decision.reasons,
            "required_actions": decision.required_actions,
        })

    @app.route("/api/v1/access/decisions", methods=["GET"])
    def access_decisions():
        n = request.args.get("n", 50, type=int)
        return jsonify({"decisions": access.recent_decisions(n)})

    @app.route("/api/v1/access/stats", methods=["GET"])
    def access_stats():
        return jsonify(access.decision_stats())

    # --- Risk ---

    @app.route("/api/v1/risk/score", methods=["POST"])
    def risk_score():
        data = request.get_json() or {}
        score = risk.calculate(
            entity_id=data.get("entity_id", ""),
            behavior_score=data.get("behavior_score", 0.0),
            device_health=data.get("device_health", 1.0),
            network_trust=data.get("network_trust", 0.5),
            source_ip=data.get("source_ip", ""),
            auth_strength=data.get("auth_strength", 0.5),
        )
        return jsonify({
            "entity_id": score.entity_id,
            "composite_score": score.composite_score,
            "risk_level": score.risk_level,
            "components": score.components,
            "factors": score.factors,
        })

    @app.route("/api/v1/risk/summary", methods=["GET"])
    def risk_summary():
        return jsonify(risk.population_risk_summary())

    # --- Policy ---

    @app.route("/api/v1/policy/evaluate", methods=["POST"])
    def policy_evaluate():
        data = request.get_json() or {}
        result = policy.evaluate(data)
        return jsonify(result)

    @app.route("/api/v1/policy/list", methods=["GET"])
    def policy_list():
        return jsonify(policy.policy_summary())

    @app.route("/api/v1/policy/conflicts", methods=["GET"])
    def policy_conflicts():
        return jsonify({"conflicts": policy.detect_conflicts()})

    # --- Behavioral ---

    @app.route("/api/v1/behavioral/observe", methods=["POST"])
    def behavioral_observe():
        data = request.get_json() or {}
        entity_id = data.get("entity_id", "")
        if not entity_id:
            return jsonify({"error": "entity_id required"}), 400
        bl.observe(entity_id, data)
        return jsonify({"status": "observed", "entity_id": entity_id})

    @app.route("/api/v1/behavioral/analyze", methods=["POST"])
    def behavioral_analyze():
        data = request.get_json() or {}
        entity_id = data.get("entity_id", "")
        result = anomaly.analyze(entity_id, data)
        return jsonify({
            "entity_id": result.entity_id,
            "anomaly_score": result.anomaly_score,
            "is_anomalous": result.is_anomalous,
            "component_scores": result.component_scores,
            "details": result.details,
        })

    @app.route("/api/v1/behavioral/profile/<entity_id>", methods=["GET"])
    def behavioral_profile(entity_id: str):
        summary = bl.profile_summary(entity_id)
        if summary is None:
            return jsonify({"error": "profile_not_found"}), 404
        return jsonify(summary)

    # --- Identity ---

    @app.route("/api/v1/identity/summary", methods=["GET"])
    def identity_summary():
        return jsonify(identity.summary())

    # --- Lateral Movement ---

    @app.route("/api/v1/lateral/detect", methods=["GET"])
    def lateral_detect():
        alerts = lateral.detect()
        return jsonify({
            "alert_count": len(alerts),
            "alerts": [
                {
                    "type": a.alert_type,
                    "severity": a.severity,
                    "path": a.path,
                    "details": a.details,
                }
                for a in alerts
            ],
        })

    return app
