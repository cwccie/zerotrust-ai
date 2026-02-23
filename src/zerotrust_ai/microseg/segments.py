"""
Segment management for microsegmentation.

Defines and manages zero-trust network segments (zones),
membership rules, and inter-segment policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Segment:
    """A microsegment / zero-trust zone."""
    segment_id: str
    name: str
    description: str = ""
    trust_level: float = 0.5  # 0.0=untrusted, 1.0=highly trusted
    members: set[str] = field(default_factory=set)
    allowed_inbound_segments: set[str] = field(default_factory=set)
    allowed_outbound_segments: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=set)
    tags: dict[str, str] = field(default_factory=dict)


class SegmentManager:
    """Manages microsegment definitions and membership."""

    def __init__(self):
        self.segments: dict[str, Segment] = {}

    def create_segment(
        self,
        segment_id: str,
        name: str,
        description: str = "",
        trust_level: float = 0.5,
    ) -> Segment:
        seg = Segment(
            segment_id=segment_id,
            name=name,
            description=description,
            trust_level=trust_level,
        )
        self.segments[segment_id] = seg
        return seg

    def add_member(self, segment_id: str, member: str) -> bool:
        seg = self.segments.get(segment_id)
        if seg is None:
            return False
        seg.members.add(member)
        return True

    def remove_member(self, segment_id: str, member: str) -> bool:
        seg = self.segments.get(segment_id)
        if seg is None:
            return False
        seg.members.discard(member)
        return True

    def get_member_segment(self, member: str) -> str | None:
        for seg in self.segments.values():
            if member in seg.members:
                return seg.segment_id
        return None

    def get_membership_map(self) -> dict[str, str]:
        """Return {member: segment_id} for all members."""
        result = {}
        for seg in self.segments.values():
            for member in seg.members:
                result[member] = seg.segment_id
        return result

    def allow_communication(
        self, from_seg: str, to_seg: str, ports: list[int] | None = None
    ) -> bool:
        src = self.segments.get(from_seg)
        dst = self.segments.get(to_seg)
        if src is None or dst is None:
            return False
        src.allowed_outbound_segments.add(to_seg)
        dst.allowed_inbound_segments.add(from_seg)
        if ports:
            dst.allowed_ports.update(ports)
        return True

    def is_allowed(self, src_member: str, dst_member: str, port: int = 0) -> bool:
        """Check if communication between two members is allowed."""
        src_seg_id = self.get_member_segment(src_member)
        dst_seg_id = self.get_member_segment(dst_member)

        if src_seg_id is None or dst_seg_id is None:
            return False  # Unknown members denied by default

        if src_seg_id == dst_seg_id:
            return True  # Same segment allowed

        src_seg = self.segments[src_seg_id]
        dst_seg = self.segments[dst_seg_id]

        if dst_seg_id not in src_seg.allowed_outbound_segments:
            return False

        if port > 0 and dst_seg.allowed_ports and port not in dst_seg.allowed_ports:
            return False

        return True

    def segment_summary(self) -> list[dict[str, Any]]:
        result = []
        for seg in self.segments.values():
            result.append({
                "segment_id": seg.segment_id,
                "name": seg.name,
                "trust_level": seg.trust_level,
                "member_count": len(seg.members),
                "allowed_inbound": list(seg.allowed_inbound_segments),
                "allowed_outbound": list(seg.allowed_outbound_segments),
            })
        return result

    def isolation_score(self) -> float:
        """Measure overall network isolation (higher = more isolated)."""
        if not self.segments:
            return 0.0
        total_possible = len(self.segments) * (len(self.segments) - 1)
        if total_possible == 0:
            return 1.0
        actual = sum(
            len(seg.allowed_outbound_segments) for seg in self.segments.values()
        )
        return round(1.0 - (actual / total_possible), 4)
