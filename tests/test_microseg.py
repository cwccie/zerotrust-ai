"""Tests for microsegmentation engine."""

import pytest

from zerotrust_ai.microseg.flows import FlowAnalyzer, Flow
from zerotrust_ai.microseg.segments import SegmentManager
from zerotrust_ai.microseg.recommender import PolicyRecommender


class TestFlowAnalyzer:
    def test_add_flow(self):
        fa = FlowAnalyzer()
        fa.add_flow(Flow(src="a", dst="b", port=80))
        assert len(fa.flows) == 1
        assert fa.adjacency["a"]["b"] == 1

    def test_get_endpoints(self, flow_analyzer):
        eps = flow_analyzer.get_endpoints()
        assert len(eps) == 6  # 3 in each cluster

    def test_communication_matrix(self, flow_analyzer):
        endpoints, matrix = flow_analyzer.communication_matrix()
        assert matrix.shape[0] == matrix.shape[1]
        assert matrix.sum() > 0

    def test_discover_clusters(self, flow_analyzer):
        clusters = flow_analyzer.discover_clusters(threshold=0.05)
        assert len(clusters) >= 1

    def test_cross_segment_flows(self, flow_analyzer):
        segments = {
            "10.1.1.1": "web", "10.1.1.2": "web", "10.1.1.3": "web",
            "10.1.2.1": "app", "10.1.2.2": "app", "10.1.2.3": "app",
        }
        cross = flow_analyzer.cross_segment_flows(segments)
        assert len(cross) > 0
        for c in cross:
            assert c["src_segment"] != c["dst_segment"]

    def test_top_talkers(self, flow_analyzer):
        talkers = flow_analyzer.top_talkers(3)
        assert len(talkers) <= 3
        assert all("total" in t for t in talkers)

    def test_port_summary(self, flow_analyzer):
        summary = flow_analyzer.port_summary()
        assert 8080 in summary or 3306 in summary


class TestSegmentManager:
    def test_create_segment(self, segment_manager):
        assert "web" in segment_manager.segments
        assert segment_manager.segments["web"].trust_level == 0.4

    def test_add_member(self, segment_manager):
        assert "10.1.1.1" in segment_manager.segments["web"].members

    def test_get_member_segment(self, segment_manager):
        assert segment_manager.get_member_segment("10.1.1.1") == "web"
        assert segment_manager.get_member_segment("unknown") is None

    def test_is_allowed_same_segment(self, segment_manager):
        assert segment_manager.is_allowed("10.1.1.1", "10.1.1.2")

    def test_is_allowed_cross_segment(self, segment_manager):
        assert segment_manager.is_allowed("10.1.1.1", "10.1.2.1", port=8080)

    def test_is_denied_wrong_port(self, segment_manager):
        assert not segment_manager.is_allowed("10.1.1.1", "10.1.2.1", port=22)

    def test_is_denied_no_rule(self, segment_manager):
        assert not segment_manager.is_allowed("10.1.1.1", "10.1.3.1")

    def test_segment_summary(self, segment_manager):
        summary = segment_manager.segment_summary()
        assert len(summary) == 3

    def test_isolation_score(self, segment_manager):
        score = segment_manager.isolation_score()
        assert 0 <= score <= 1.0

    def test_remove_member(self, segment_manager):
        assert segment_manager.remove_member("web", "10.1.1.1")
        assert "10.1.1.1" not in segment_manager.segments["web"].members

    def test_get_membership_map(self, segment_manager):
        m = segment_manager.get_membership_map()
        assert m["10.1.1.1"] == "web"
        assert m["10.1.2.1"] == "app"


class TestPolicyRecommender:
    def test_recommend(self, flow_analyzer, segment_manager):
        # Assign flow hosts to segments
        for h in ["10.1.1.1", "10.1.1.2", "10.1.1.3"]:
            segment_manager.add_member("web", h)
        for h in ["10.1.2.1", "10.1.2.2", "10.1.2.3"]:
            segment_manager.add_member("app", h)

        rec = PolicyRecommender(flow_analyzer, segment_manager, min_flow_count=3)
        recommendations = rec.recommend()
        assert isinstance(recommendations, list)

    def test_coverage_report(self, flow_analyzer, segment_manager):
        for h in ["10.1.1.1", "10.1.1.2", "10.1.1.3"]:
            segment_manager.add_member("web", h)

        rec = PolicyRecommender(flow_analyzer, segment_manager)
        report = rec.coverage_report()
        assert "total_flows" in report
        assert "coverage_pct" in report
