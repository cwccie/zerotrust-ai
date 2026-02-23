"""Tests for behavioral analytics engine."""

import numpy as np
import pytest

from zerotrust_ai.behavioral import BehavioralBaseline, AnomalyDetector, SessionAnalyzer, PatternAnalyzer


class TestBehavioralBaseline:
    def test_create_profile(self):
        bl = BehavioralBaseline()
        profile = bl.get_or_create_profile("user-1", "user")
        assert profile.entity_id == "user-1"
        assert profile.entity_type == "user"
        assert profile.observation_count == 0

    def test_observe_updates_count(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert profile is not None
        assert profile.observation_count == 100

    def test_observe_hour_distribution(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert profile.hour_distribution.sum() > 0
        probs = profile.hour_probabilities()
        assert abs(probs.sum() - 1.0) < 1e-10

    def test_observe_dow_distribution(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert profile.dow_distribution.sum() > 0

    def test_observe_resource_frequencies(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert len(profile.resource_frequencies) > 0
        assert all(v > 0 for v in profile.resource_frequencies.values())

    def test_session_duration_stats(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert profile.session_count > 0
        assert profile.session_duration_mean > 0
        assert profile.session_duration_std > 0

    def test_location_tracking(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert "us-east" in profile.locations_seen
        assert profile.locations_seen["us-east"] == 100

    def test_ip_tracking(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        assert len(profile.source_ips) > 0

    def test_observe_batch(self):
        bl = BehavioralBaseline()
        events = [{"hour": i, "resource": f"r{i}"} for i in range(10)]
        profile = bl.observe_batch("user-x", events)
        assert profile.observation_count == 10

    def test_decay_profiles(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        before = profile.hour_distribution.sum()
        baseline_engine.decay_profiles()
        after = profile.hour_distribution.sum()
        assert after < before

    def test_profile_summary(self, baseline_engine):
        summary = baseline_engine.profile_summary("user-001")
        assert summary is not None
        assert summary["entity_id"] == "user-001"
        assert summary["observation_count"] == 100
        assert "peak_hour" in summary
        assert "avg_session_duration" in summary

    def test_profile_summary_missing(self, baseline_engine):
        assert baseline_engine.profile_summary("nonexistent") is None

    def test_all_entity_ids(self, baseline_engine):
        ids = baseline_engine.all_entity_ids()
        assert len(ids) == 3
        assert "user-001" in ids

    def test_top_resources(self, baseline_engine):
        profile = baseline_engine.get_profile("user-001")
        top = profile.top_resources(2)
        assert len(top) <= 2
        assert all(isinstance(t, tuple) for t in top)

    def test_custom_features(self):
        bl = BehavioralBaseline()
        bl.observe("u1", {"features": {"bytes_sent": 100.0}})
        bl.observe("u1", {"features": {"bytes_sent": 200.0}})
        profile = bl.get_profile("u1")
        mean, m2, count = profile.feature_stats["bytes_sent"]
        assert count == 2
        assert abs(mean - 150.0) < 1e-10


class TestAnomalyDetector:
    def test_analyze_normal_event(self, anomaly_detector):
        result = anomaly_detector.analyze("user-001", {
            "hour": 10, "resource": "db-prod", "location": "us-east",
            "source_ip": "10.0.1.15", "session_duration": 3600,
        })
        assert result.anomaly_score < 0.6
        assert not result.is_anomalous

    def test_analyze_anomalous_event(self, anomaly_detector):
        result = anomaly_detector.analyze("user-001", {
            "hour": 3, "resource": "unknown-resource", "location": "cn-north",
            "source_ip": "203.0.113.99", "session_duration": 36000,
        })
        assert result.anomaly_score > 0.5
        assert result.is_anomalous

    def test_analyze_unknown_entity(self, anomaly_detector):
        result = anomaly_detector.analyze("unknown-user", {"hour": 10})
        assert not result.is_anomalous
        assert result.details.get("reason") == "insufficient_baseline"

    def test_analyze_batch(self, anomaly_detector):
        events = [
            {"hour": 10, "resource": "db-prod"},
            {"hour": 3, "location": "cn-north"},
        ]
        results = anomaly_detector.analyze_batch("user-001", events)
        assert len(results) == 2

    def test_component_scores(self, anomaly_detector):
        result = anomaly_detector.analyze("user-001", {
            "hour": 3, "resource": "db-prod", "location": "us-east",
            "source_ip": "10.0.1.15",
        })
        assert "time" in result.component_scores
        assert "resource" in result.component_scores

    def test_novel_location_high_score(self, anomaly_detector):
        result = anomaly_detector.analyze("user-001", {"location": "moon-base"})
        assert result.component_scores.get("location", 0) > 0.7

    def test_novel_ip_high_score(self, anomaly_detector):
        result = anomaly_detector.analyze("user-001", {"source_ip": "192.168.99.99"})
        assert result.component_scores.get("ip", 0) > 0.5

    def test_extreme_duration_high_score(self, anomaly_detector):
        result = anomaly_detector.analyze("user-001", {"session_duration": 100000})
        assert result.component_scores.get("duration", 0) > 0.3


class TestSessionAnalyzer:
    def test_start_session(self):
        sa = SessionAnalyzer(max_concurrent=2)
        result = sa.start_session("s1", "alice", source_ip="10.0.1.1")
        assert result["concurrent_count"] == 1
        assert len(result["risks"]) == 0

    def test_concurrent_session_limit(self):
        sa = SessionAnalyzer(max_concurrent=2)
        sa.start_session("s1", "alice", source_ip="10.0.1.1")
        sa.start_session("s2", "alice", source_ip="10.0.1.1")
        result = sa.start_session("s3", "alice", source_ip="10.0.1.1")
        assert "excessive_concurrent_sessions" in result["risks"]

    def test_different_ip_risk(self):
        sa = SessionAnalyzer()
        sa.start_session("s1", "alice", source_ip="10.0.1.1")
        result = sa.start_session("s2", "alice", source_ip="203.0.113.50")
        assert "multiple_source_ips" in result["risks"]

    def test_update_session(self):
        sa = SessionAnalyzer()
        sa.start_session("s1", "alice")
        result = sa.update_session("s1", action="read")
        assert result["action_count"] == 1

    def test_end_session(self):
        sa = SessionAnalyzer()
        sa.start_session("s1", "alice")
        result = sa.end_session("s1")
        assert result["duration"] >= 0

    def test_get_active_sessions(self):
        sa = SessionAnalyzer()
        sa.start_session("s1", "alice")
        sa.start_session("s2", "alice")
        sa.end_session("s1")
        active = sa.get_active_sessions("alice")
        assert len(active) == 1
        assert active[0]["session_id"] == "s2"

    def test_ip_change_mid_session(self):
        sa = SessionAnalyzer()
        sa.start_session("s1", "alice", source_ip="10.0.1.1")
        result = sa.update_session("s1", source_ip="10.0.2.99")
        assert "ip_changed_mid_session" in result["risks"]


class TestPatternAnalyzer:
    def test_time_anomaly(self, baseline_engine):
        pa = PatternAnalyzer(baseline_engine=baseline_engine)
        result = pa.detect_time_anomaly("user-001", hour=3, day_of_week=6)
        assert "score" in result
        assert result["score"] > 0

    def test_geographic_anomaly_novel(self, baseline_engine):
        pa = PatternAnalyzer(baseline_engine=baseline_engine)
        result = pa.detect_geographic_anomaly("user-001", "moon-base")
        assert result["anomalous"]
        assert result["score"] > 0.8

    def test_geographic_anomaly_known(self, baseline_engine):
        pa = PatternAnalyzer(baseline_engine=baseline_engine)
        result = pa.detect_geographic_anomaly("user-001", "us-east")
        assert not result["anomalous"]

    def test_entropy_score(self, baseline_engine):
        pa = PatternAnalyzer(baseline_engine=baseline_engine)
        result = pa.entropy_score("user-001")
        assert "hour_entropy" in result
        assert result["hour_entropy"] > 0

    def test_population_outliers(self, baseline_engine):
        pa = PatternAnalyzer(baseline_engine=baseline_engine)
        # All have same count, so no outliers expected
        outliers = pa.population_outliers("observation_count")
        assert isinstance(outliers, list)
