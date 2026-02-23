"""
Policy recommendation engine for microsegmentation.

Analyzes observed flows and generates least-privilege
microsegmentation policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .flows import FlowAnalyzer
from .segments import SegmentManager


@dataclass
class PolicyRecommendation:
    """A recommended microsegmentation policy."""
    src_segment: str
    dst_segment: str
    allowed_ports: list[int]
    protocol: str = "tcp"
    confidence: float = 0.0
    reason: str = ""


class PolicyRecommender:
    """Generates microsegmentation policy recommendations from flow data."""

    def __init__(
        self,
        flow_analyzer: FlowAnalyzer,
        segment_manager: SegmentManager,
        min_flow_count: int = 5,
    ):
        self.flows = flow_analyzer
        self.segments = segment_manager
        self.min_flow_count = min_flow_count

    def recommend(self) -> list[PolicyRecommendation]:
        """Generate policy recommendations based on observed flows."""
        membership = self.segments.get_membership_map()
        seg_flows: dict[tuple[str, str], dict[str, Any]] = {}

        for flow in self.flows.flows:
            src_seg = membership.get(flow.src)
            dst_seg = membership.get(flow.dst)
            if src_seg is None or dst_seg is None:
                continue
            if src_seg == dst_seg:
                continue

            key = (src_seg, dst_seg)
            if key not in seg_flows:
                seg_flows[key] = {"count": 0, "ports": set(), "protocols": set()}

            seg_flows[key]["count"] += 1
            seg_flows[key]["ports"].add(flow.port)
            seg_flows[key]["protocols"].add(flow.protocol)

        recommendations = []
        for (src, dst), data in seg_flows.items():
            if data["count"] < self.min_flow_count:
                continue

            confidence = min(1.0, data["count"] / 100.0)
            rec = PolicyRecommendation(
                src_segment=src,
                dst_segment=dst,
                allowed_ports=sorted(data["ports"]),
                protocol=",".join(sorted(data["protocols"])),
                confidence=round(confidence, 4),
                reason=f"Observed {data['count']} flows across {len(data['ports'])} ports",
            )
            recommendations.append(rec)

        return sorted(recommendations, key=lambda r: r.confidence, reverse=True)

    def recommend_segments(self) -> list[dict[str, Any]]:
        """Recommend new segments based on flow clustering."""
        clusters = self.flows.discover_clusters()
        recommendations = []

        for i, cluster in enumerate(clusters):
            # Find existing segment overlap
            existing = set()
            for member in cluster:
                seg = self.segments.get_member_segment(member)
                if seg:
                    existing.add(seg)

            if not existing:
                recommendations.append({
                    "suggested_segment": f"auto-seg-{i}",
                    "members": sorted(cluster),
                    "reason": f"Cluster of {len(cluster)} frequently communicating endpoints",
                    "confidence": min(1.0, len(cluster) / 5.0),
                })

        return recommendations

    def coverage_report(self) -> dict[str, Any]:
        """Report on how well current segments cover observed traffic."""
        membership = self.segments.get_membership_map()
        total = len(self.flows.flows)
        covered = 0
        uncovered_endpoints: set[str] = set()

        for flow in self.flows.flows:
            src_has = flow.src in membership
            dst_has = flow.dst in membership
            if src_has and dst_has:
                covered += 1
            if not src_has:
                uncovered_endpoints.add(flow.src)
            if not dst_has:
                uncovered_endpoints.add(flow.dst)

        return {
            "total_flows": total,
            "covered_flows": covered,
            "coverage_pct": round(covered / total * 100, 1) if total > 0 else 0,
            "uncovered_endpoints": sorted(uncovered_endpoints),
            "segments_defined": len(self.segments.segments),
        }
