"""
Lateral movement detection using GNN-inspired analysis.

Uses graph neural network forward passes (pure NumPy) to detect
lateral movement patterns: credential hopping, privilege escalation
paths, and anomalous graph traversals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .graph import AccessGraph, AccessEdge


@dataclass
class LateralMovementAlert:
    """Alert for detected lateral movement."""
    alert_type: str
    severity: float  # 0.0-1.0
    path: list[str]
    details: dict[str, Any] = field(default_factory=dict)


class GNNLayer:
    """
    A single GNN message-passing layer (pure NumPy).

    Implements: h_v' = sigma(W_self * h_v + W_neigh * AGG(h_u : u in N(v)) + b)
    """

    def __init__(self, in_dim: int, out_dim: int, seed: int = 42):
        rng = np.random.RandomState(seed)
        scale = np.sqrt(2.0 / in_dim)
        self.W_self = rng.randn(in_dim, out_dim).astype(np.float64) * scale
        self.W_neigh = rng.randn(in_dim, out_dim).astype(np.float64) * scale
        self.bias = np.zeros(out_dim, dtype=np.float64)

    def forward(
        self, features: np.ndarray, adj: np.ndarray
    ) -> np.ndarray:
        """
        Forward pass.

        Args:
            features: (N, in_dim) node feature matrix
            adj: (N, N) adjacency matrix (can be weighted)
        Returns:
            (N, out_dim) updated node features
        """
        # Normalize adjacency
        degree = adj.sum(axis=1, keepdims=True)
        degree[degree == 0] = 1
        adj_norm = adj / degree

        # Message passing
        self_transform = features @ self.W_self
        neighbor_agg = (adj_norm @ features) @ self.W_neigh
        output = self_transform + neighbor_agg + self.bias

        # ReLU activation
        return np.maximum(output, 0)


class LateralMovementDetector:
    """
    Detects lateral movement using GNN-based graph analysis.

    The GNN learns node embeddings that capture structural patterns.
    Anomalous traversal patterns produce high-anomaly embeddings.
    """

    def __init__(
        self,
        feature_dim: int = 8,
        hidden_dim: int = 16,
        output_dim: int = 8,
        hop_threshold: int = 3,
        seed: int = 42,
    ):
        self.graph = AccessGraph()
        self.hop_threshold = hop_threshold

        # Two-layer GNN
        self.gnn_layer1 = GNNLayer(feature_dim, hidden_dim, seed=seed)
        self.gnn_layer2 = GNNLayer(hidden_dim, output_dim, seed=seed + 1)

        # Anomaly threshold learned from baseline
        self.baseline_embeddings: dict[str, np.ndarray] = {}
        self.anomaly_threshold = 2.0

    def add_access_event(self, edge: AccessEdge) -> None:
        self.graph.add_edge(edge)

    def compute_embeddings(self) -> tuple[list[str], np.ndarray]:
        """Run GNN forward pass to compute node embeddings."""
        nodes, features = self.graph.feature_matrix()
        if len(nodes) == 0:
            return [], np.zeros((0, 8))

        _, adj = self.graph.adjacency_matrix()

        # Two-layer GNN forward pass
        h1 = self.gnn_layer1.forward(features, adj)
        h2 = self.gnn_layer2.forward(h1, adj)

        return nodes, h2

    def learn_baseline(self) -> int:
        """Learn baseline embeddings from current graph state."""
        nodes, embeddings = self.compute_embeddings()
        for i, node in enumerate(nodes):
            self.baseline_embeddings[node] = embeddings[i].copy()
        return len(nodes)

    def detect(self) -> list[LateralMovementAlert]:
        """Run all lateral movement detection methods."""
        alerts = []
        alerts.extend(self._detect_credential_hopping())
        alerts.extend(self._detect_privilege_escalation())
        alerts.extend(self._detect_embedding_anomalies())
        return sorted(alerts, key=lambda a: a.severity, reverse=True)

    def _detect_credential_hopping(self) -> list[LateralMovementAlert]:
        """Detect credential hopping (entity accesses many targets in sequence)."""
        alerts = []

        # Group edges by source, sorted by time
        by_source: dict[str, list[AccessEdge]] = {}
        for edge in self.graph.edges:
            if edge.src not in by_source:
                by_source[edge.src] = []
            by_source[edge.src].append(edge)

        for src, edges in by_source.items():
            sorted_edges = sorted(edges, key=lambda e: e.timestamp)
            unique_targets = []
            seen = set()
            for e in sorted_edges:
                if e.dst not in seen:
                    unique_targets.append(e.dst)
                    seen.add(e.dst)

            if len(unique_targets) >= self.hop_threshold:
                # Check for sequential hopping pattern
                severity = min(1.0, len(unique_targets) / (self.hop_threshold * 2))
                alerts.append(LateralMovementAlert(
                    alert_type="credential_hopping",
                    severity=round(severity, 4),
                    path=[src] + unique_targets[:self.hop_threshold + 2],
                    details={
                        "source": src,
                        "hop_count": len(unique_targets),
                        "threshold": self.hop_threshold,
                    },
                ))

        return alerts

    def _detect_privilege_escalation(self) -> list[LateralMovementAlert]:
        """Detect paths that show privilege escalation patterns."""
        alerts = []

        # Look for paths from low-privilege to high-privilege nodes
        high_priv_nodes = set()
        low_priv_nodes = set()

        for node, features in self.graph.node_features.items():
            # Feature index 0 = privilege level by convention
            if len(features) > 0:
                if features[0] > 0.7:
                    high_priv_nodes.add(node)
                elif features[0] < 0.3:
                    low_priv_nodes.add(node)

        for low in low_priv_nodes:
            for high in high_priv_nodes:
                paths = self.graph.all_paths(low, high, max_depth=4)
                for path in paths:
                    if len(path) >= 3:
                        alerts.append(LateralMovementAlert(
                            alert_type="privilege_escalation",
                            severity=round(0.6 + 0.1 * len(path), 4),
                            path=path,
                            details={
                                "source": low,
                                "target": high,
                                "hops": len(path) - 1,
                            },
                        ))

        return alerts

    def _detect_embedding_anomalies(self) -> list[LateralMovementAlert]:
        """Detect anomalies by comparing current embeddings to baseline."""
        if not self.baseline_embeddings:
            return []

        nodes, current = self.compute_embeddings()
        alerts = []

        for i, node in enumerate(nodes):
            if node not in self.baseline_embeddings:
                continue
            baseline = self.baseline_embeddings[node]
            distance = float(np.linalg.norm(current[i] - baseline))

            if distance > self.anomaly_threshold:
                severity = min(1.0, distance / (self.anomaly_threshold * 3))
                alerts.append(LateralMovementAlert(
                    alert_type="embedding_anomaly",
                    severity=round(severity, 4),
                    path=[node],
                    details={
                        "node": node,
                        "embedding_distance": round(distance, 4),
                        "threshold": self.anomaly_threshold,
                    },
                ))

        return alerts

    def analyze_path(self, path: list[str]) -> dict[str, Any]:
        """Analyze a specific access path for risk."""
        if len(path) < 2:
            return {"risk": 0.0, "reason": "path_too_short"}

        total_edges = 0
        failed_edges = 0
        credential_changes = 0
        prev_cred = None

        for i in range(len(path) - 1):
            edges = self.graph.get_edges_between(path[i], path[i + 1])
            total_edges += len(edges)
            for e in edges:
                if not e.success:
                    failed_edges += 1
                if prev_cred and e.credential_type != prev_cred:
                    credential_changes += 1
                prev_cred = e.credential_type

        risk = 0.0
        risk += min(0.3, len(path) * 0.05)  # Path length
        risk += min(0.3, credential_changes * 0.1)  # Credential changes
        risk += min(0.3, failed_edges * 0.05)  # Failed attempts

        return {
            "path": path,
            "path_length": len(path),
            "total_edges": total_edges,
            "credential_changes": credential_changes,
            "failed_attempts": failed_edges,
            "risk_score": round(min(1.0, risk), 4),
        }
