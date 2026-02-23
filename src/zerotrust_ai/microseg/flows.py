"""
Network flow analysis for microsegmentation.

Discovers communication patterns between workloads by analyzing
flow data, identifying clusters of related services, and detecting
unexpected cross-segment traffic.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class Flow:
    """A single observed network flow."""
    src: str
    dst: str
    port: int
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_recv: int = 0
    timestamp: float = 0.0
    duration: float = 0.0
    allowed: bool = True


class FlowAnalyzer:
    """
    Analyzes network flows to discover communication patterns
    and identify microsegmentation opportunities.
    """

    def __init__(self):
        self.flows: list[Flow] = []
        self.adjacency: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.port_map: dict[str, set[int]] = defaultdict(set)
        self.protocol_map: dict[str, set[str]] = defaultdict(set)

    def add_flow(self, flow: Flow) -> None:
        self.flows.append(flow)
        self.adjacency[flow.src][flow.dst] += 1
        key = f"{flow.src}->{flow.dst}"
        self.port_map[key].add(flow.port)
        self.protocol_map[key].add(flow.protocol)

    def add_flows(self, flows: list[Flow]) -> None:
        for f in flows:
            self.add_flow(f)

    def get_endpoints(self) -> set[str]:
        endpoints = set()
        for flow in self.flows:
            endpoints.add(flow.src)
            endpoints.add(flow.dst)
        return endpoints

    def communication_matrix(self) -> tuple[list[str], np.ndarray]:
        """Build a communication frequency matrix."""
        endpoints = sorted(self.get_endpoints())
        idx = {ep: i for i, ep in enumerate(endpoints)}
        n = len(endpoints)
        matrix = np.zeros((n, n), dtype=np.float64)

        for src, dsts in self.adjacency.items():
            if src in idx:
                for dst, count in dsts.items():
                    if dst in idx:
                        matrix[idx[src]][idx[dst]] = count

        return endpoints, matrix

    def discover_clusters(self, threshold: float = 0.1) -> list[set[str]]:
        """
        Discover communication clusters using spectral-like grouping.

        Endpoints that frequently communicate are grouped together.
        """
        endpoints, matrix = self.communication_matrix()
        if len(endpoints) < 2:
            return [set(endpoints)] if endpoints else []

        # Normalize to get affinity matrix
        row_sums = matrix.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        affinity = (matrix + matrix.T) / (2 * row_sums.max())

        # Simple greedy clustering based on affinity
        assigned = set()
        clusters: list[set[str]] = []

        for i, ep in enumerate(endpoints):
            if ep in assigned:
                continue
            cluster = {ep}
            assigned.add(ep)

            for j, other in enumerate(endpoints):
                if other in assigned:
                    continue
                if affinity[i][j] > threshold or affinity[j][i] > threshold:
                    cluster.add(other)
                    assigned.add(other)

            clusters.append(cluster)

        return clusters

    def cross_segment_flows(
        self, segments: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Identify flows that cross segment boundaries."""
        cross = []
        for flow in self.flows:
            src_seg = segments.get(flow.src, "unknown")
            dst_seg = segments.get(flow.dst, "unknown")
            if src_seg != dst_seg:
                cross.append({
                    "src": flow.src,
                    "dst": flow.dst,
                    "src_segment": src_seg,
                    "dst_segment": dst_seg,
                    "port": flow.port,
                    "protocol": flow.protocol,
                })
        return cross

    def top_talkers(self, n: int = 10) -> list[dict[str, Any]]:
        """Find endpoints with the most communication."""
        out_count: dict[str, int] = defaultdict(int)
        in_count: dict[str, int] = defaultdict(int)
        for flow in self.flows:
            out_count[flow.src] += 1
            in_count[flow.dst] += 1

        all_eps = set(list(out_count.keys()) + list(in_count.keys()))
        talkers = []
        for ep in all_eps:
            talkers.append({
                "endpoint": ep,
                "outbound": out_count.get(ep, 0),
                "inbound": in_count.get(ep, 0),
                "total": out_count.get(ep, 0) + in_count.get(ep, 0),
            })

        return sorted(talkers, key=lambda x: x["total"], reverse=True)[:n]

    def port_summary(self) -> dict[int, int]:
        """Count flows by destination port."""
        counts: dict[int, int] = defaultdict(int)
        for flow in self.flows:
            counts[flow.port] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
