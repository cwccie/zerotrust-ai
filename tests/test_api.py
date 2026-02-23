"""Tests for REST API."""

import json

import pytest

from zerotrust_ai.api import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestAPI:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "healthy"

    def test_access_decide(self, client):
        r = client.post("/api/v1/access/decide", json={
            "entity_id": "alice",
            "resource": "docs",
            "action": "read",
            "network_zone": "internal",
            "auth_method": "certificate",
            "mfa_verified": True,
            "device_compliance": 1.0,
        })
        assert r.status_code == 200
        data = r.get_json()
        assert "decision" in data

    def test_access_decisions_list(self, client):
        client.post("/api/v1/access/decide", json={"entity_id": "x", "resource": "r"})
        r = client.get("/api/v1/access/decisions")
        assert r.status_code == 200
        data = r.get_json()
        assert "decisions" in data

    def test_access_stats(self, client):
        r = client.get("/api/v1/access/stats")
        assert r.status_code == 200

    def test_risk_score(self, client):
        r = client.post("/api/v1/risk/score", json={
            "entity_id": "alice",
            "behavior_score": 0.1,
            "device_health": 0.9,
        })
        assert r.status_code == 200
        data = r.get_json()
        assert "composite_score" in data

    def test_risk_summary(self, client):
        r = client.get("/api/v1/risk/summary")
        assert r.status_code == 200

    def test_behavioral_observe(self, client):
        r = client.post("/api/v1/behavioral/observe", json={
            "entity_id": "alice",
            "hour": 10,
            "resource": "docs",
        })
        assert r.status_code == 200
        assert r.get_json()["status"] == "observed"

    def test_behavioral_observe_no_entity(self, client):
        r = client.post("/api/v1/behavioral/observe", json={})
        assert r.status_code == 400

    def test_behavioral_analyze(self, client):
        r = client.post("/api/v1/behavioral/analyze", json={
            "entity_id": "alice", "hour": 3,
        })
        assert r.status_code == 200
        assert "anomaly_score" in r.get_json()

    def test_behavioral_profile_not_found(self, client):
        r = client.get("/api/v1/behavioral/profile/nonexistent")
        assert r.status_code == 404

    def test_policy_evaluate(self, client):
        r = client.post("/api/v1/policy/evaluate", json={"risk_score": 0.5})
        assert r.status_code == 200

    def test_policy_list(self, client):
        r = client.get("/api/v1/policy/list")
        assert r.status_code == 200

    def test_policy_conflicts(self, client):
        r = client.get("/api/v1/policy/conflicts")
        assert r.status_code == 200

    def test_identity_summary(self, client):
        r = client.get("/api/v1/identity/summary")
        assert r.status_code == 200

    def test_lateral_detect(self, client):
        r = client.get("/api/v1/lateral/detect")
        assert r.status_code == 200
        data = r.get_json()
        assert "alert_count" in data
