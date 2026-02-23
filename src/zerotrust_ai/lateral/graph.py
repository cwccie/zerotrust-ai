"""
Access graph for lateral movement analysis.

Builds and maintains a graph of access patterns between entities
and resources, enabling graph-based anomaly detection.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class AccessEdge:
    """An edge in the access graph representing an access event."""
    src: str
    dst: str
    action: str = "access"
    timestamp: float = 0.0
    credential_type: str = "password"
    success: bool = True
    risk_score: float = 0.0


class AccessGraph:
    """
    Graph representation of access patterns for lateral movement detection.

    Nodes are entities (users, devices, services, resources).
    Edges are access events with metadata.
    """

    def __init__(self):
        self.edges: list[AccessEdge] = []
        self.adjacency: dict[str, dict[str, list[AccessEdge]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.node_types: dict[str, str] = {}
        self.node_features: dict[str, np.ndarray] = {}

    def add_node(
        self, node_id: str, node_type: str = "entity", features: np.ndarray | None = None
    ) -> None:
        self.node_types[node_id] = node_type
        if features is not None:
            self.node_features[node_id] = features
        else:
            self.node_features[node_id] = np.zeros(8, dtype=np.float64)

    def add_edge(self, edge: AccessEdge) -> None:
        self.edges.append(edge)
        self.adjacency[edge.src][edge.dst].append(edge)
        # Ensure nodes exist
        if edge.src not in self.node_types:
            self.add_node(edge.src, "entity")
        if edge.dst not in self.node_types:
            self.add_node(edge.dst, "resource")

    def get_neighbors(self, node_id: str) -> set[str]:
        return set(self.adjacency.get(node_id, {}).keys())

    def get_edges_between(self, src: str, dst: str) -> list[AccessEdge]:
        return self.adjacency.get(src, {}).get(dst, [])

    def adjacency_matrix(self) -> tuple[list[str], np.ndarray]:
        """Build adjacency matrix for all nodes."""
        nodes = sorted(set(self.node_types.keys()))
        idx = {n: i for i, n in enumerate(nodes)}
        n = len(nodes)
        mat = np.zeros((n, n), dtype=np.float64)

        for src, dsts in self.adjacency.items():
            if src in idx:
                for dst, edges in dsts.items():
                    if dst in idx:
                        mat[idx[src]][idx[dst]] = len(edges)

        return nodes, mat

    def feature_matrix(self) -> tuple[list[str], np.ndarray]:
        """Build node feature matrix."""
        nodes = sorted(self.node_features.keys())
        if not nodes:
            return [], np.zeros((0, 8))

        dim = len(next(iter(self.node_features.values())))
        mat = np.zeros((len(nodes), dim), dtype=np.float64)
        for i, node in enumerate(nodes):
            mat[i] = self.node_features[node]

        return nodes, mat

    def shortest_path(self, src: str, dst: str) -> list[str] | None:
        """BFS shortest path between two nodes."""
        if src == dst:
            return [src]

        visited = {src}
        queue = [(src, [src])]

        while queue:
            current, path = queue.pop(0)
            for neighbor in self.get_neighbors(current):
                if neighbor == dst:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def all_paths(self, src: str, dst: str, max_depth: int = 5) -> list[list[str]]:
        """Find all paths up to max_depth using DFS."""
        paths: list[list[str]] = []

        def dfs(current: str, target: str, path: list[str], visited: set[str]):
            if len(path) > max_depth:
                return
            if current == target:
                paths.append(path[:])
                return
            for neighbor in self.get_neighbors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, target, path, visited)
                    path.pop()
                    visited.remove(neighbor)

        dfs(src, dst, [src], {src})
        return paths

    def node_degree(self, node_id: str) -> dict[str, int]:
        out_degree = len(self.adjacency.get(node_id, {}))
        in_degree = sum(
            1 for src in self.adjacency
            if node_id in self.adjacency[src]
        )
        return {"in": in_degree, "out": out_degree, "total": in_degree + out_degree}

    def high_centrality_nodes(self, top_n: int = 10) -> list[dict[str, Any]]:
        """Find nodes with highest degree centrality."""
        results = []
        for node in self.node_types:
            deg = self.node_degree(node)
            results.append({
                "node_id": node,
                "node_type": self.node_types[node],
                "degree": deg["total"],
                "in_degree": deg["in"],
                "out_degree": deg["out"],
            })
        return sorted(results, key=lambda x: x["degree"], reverse=True)[:top_n]
