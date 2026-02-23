"""Tests for lateral movement detection."""

import time

import numpy as np
import pytest

from zerotrust_ai.lateral import LateralMovementDetector, AccessGraph
from zerotrust_ai.lateral.graph import AccessEdge


class TestAccessGraph:
    def test_add_node(self):
        g = AccessGraph()
        g.add_node("h1", "host", np.ones(8))
        assert "h1" in g.node_types
        assert g.node_types["h1"] == "host"

    def test_add_edge(self):
        g = AccessGraph()
        g.add_edge(AccessEdge(src="a", dst="b", action="ssh"))
        assert "b" in g.get_neighbors("a")

    def test_adjacency_matrix(self, access_graph):
        nodes, mat = access_graph.adjacency_matrix()
        assert len(nodes) == 6
        assert mat.shape == (6, 6)
        assert mat.sum() > 0

    def test_feature_matrix(self, access_graph):
        nodes, mat = access_graph.feature_matrix()
        assert mat.shape[0] == 6
        assert mat.shape[1] == 8

    def test_shortest_path(self, access_graph):
        path = access_graph.shortest_path("host-04", "host-01")
        assert path is not None
        assert path[0] == "host-04"
        assert path[-1] == "host-01"

    def test_shortest_path_no_path(self):
        g = AccessGraph()
        g.add_node("a", "host")
        g.add_node("b", "host")
        assert g.shortest_path("a", "b") is None

    def test_shortest_path_same_node(self, access_graph):
        path = access_graph.shortest_path("host-01", "host-01")
        assert path == ["host-01"]

    def test_all_paths(self, access_graph):
        paths = access_graph.all_paths("host-04", "host-01", max_depth=5)
        assert len(paths) > 0
        for path in paths:
            assert path[0] == "host-04"
            assert path[-1] == "host-01"

    def test_node_degree(self, access_graph):
        deg = access_graph.node_degree("host-03")
        assert deg["total"] > 0

    def test_high_centrality_nodes(self, access_graph):
        top = access_graph.high_centrality_nodes(3)
        assert len(top) <= 3
        assert all("degree" in n for n in top)


class TestLateralMovementDetector:
    def test_compute_embeddings(self, np_rng):
        det = LateralMovementDetector()
        for i in range(4):
            det.graph.add_node(f"h{i}", "host", np_rng.rand(8))
        det.add_access_event(AccessEdge(src="h0", dst="h1"))
        det.add_access_event(AccessEdge(src="h1", dst="h2"))

        nodes, emb = det.compute_embeddings()
        assert len(nodes) == 4
        assert emb.shape[1] == 8  # output_dim

    def test_learn_baseline(self, np_rng):
        det = LateralMovementDetector()
        for i in range(3):
            det.graph.add_node(f"h{i}", "host", np_rng.rand(8))
        det.add_access_event(AccessEdge(src="h0", dst="h1"))
        count = det.learn_baseline()
        assert count == 3
        assert len(det.baseline_embeddings) == 3

    def test_detect_credential_hopping(self):
        det = LateralMovementDetector(hop_threshold=3)
        # Create hopping chain
        for i in range(6):
            det.add_access_event(AccessEdge(
                src="attacker", dst=f"target-{i}",
                action="ssh", timestamp=time.time() + i * 10,
            ))

        alerts = det._detect_credential_hopping()
        assert len(alerts) > 0
        assert alerts[0].alert_type == "credential_hopping"

    def test_detect_privilege_escalation(self, np_rng):
        det = LateralMovementDetector()
        # Low priv node
        low_feat = np_rng.rand(8)
        low_feat[0] = 0.1
        det.graph.add_node("low", "host", low_feat)

        # Mid node
        mid_feat = np_rng.rand(8)
        mid_feat[0] = 0.5
        det.graph.add_node("mid", "host", mid_feat)

        # High priv node
        high_feat = np_rng.rand(8)
        high_feat[0] = 0.9
        det.graph.add_node("high", "host", high_feat)

        det.add_access_event(AccessEdge(src="low", dst="mid"))
        det.add_access_event(AccessEdge(src="mid", dst="high"))

        alerts = det._detect_privilege_escalation()
        assert len(alerts) > 0
        assert alerts[0].alert_type == "privilege_escalation"

    def test_detect_full(self, np_rng):
        det = LateralMovementDetector(hop_threshold=2)
        for i in range(5):
            feats = np_rng.rand(8)
            feats[0] = 0.1 if i == 4 else (0.9 if i == 0 else 0.5)
            det.graph.add_node(f"h{i}", "host", feats)

        for i in range(4):
            det.add_access_event(AccessEdge(
                src=f"h{i+1}", dst=f"h{i}", timestamp=time.time() + i,
            ))

        det.learn_baseline()
        # Add new edge to trigger embedding change
        det.add_access_event(AccessEdge(src="h4", dst="h0", timestamp=time.time() + 100))

        alerts = det.detect()
        assert isinstance(alerts, list)

    def test_analyze_path(self):
        det = LateralMovementDetector()
        det.add_access_event(AccessEdge(
            src="a", dst="b", credential_type="password", success=True,
        ))
        det.add_access_event(AccessEdge(
            src="b", dst="c", credential_type="token", success=False,
        ))
        result = det.analyze_path(["a", "b", "c"])
        assert result["path_length"] == 3
        assert result["credential_changes"] >= 0
        assert 0 <= result["risk_score"] <= 1.0

    def test_gnn_forward_pass(self):
        from zerotrust_ai.lateral.detector import GNNLayer
        layer = GNNLayer(8, 16)
        features = np.random.rand(5, 8)
        adj = np.random.rand(5, 5)
        output = layer.forward(features, adj)
        assert output.shape == (5, 16)
        assert (output >= 0).all()  # ReLU
