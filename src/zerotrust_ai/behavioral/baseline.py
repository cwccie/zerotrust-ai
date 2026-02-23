"""
Behavioral baseline learning engine.

Learns normal behavior patterns for users, devices, and services
using statistical modeling with online (streaming) updates.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class BaselineProfile:
    """Statistical profile representing normal behavior for an entity."""

    entity_id: str
    entity_type: str  # "user", "device", "service"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    observation_count: int = 0

    # Time-of-day distribution (24 bins)
    hour_distribution: np.ndarray = field(
        default_factory=lambda: np.zeros(24, dtype=np.float64)
    )
    # Day-of-week distribution (7 bins)
    dow_distribution: np.ndarray = field(
        default_factory=lambda: np.zeros(7, dtype=np.float64)
    )
    # Resource access frequencies
    resource_frequencies: dict[str, int] = field(default_factory=dict)
    # Action type frequencies
    action_frequencies: dict[str, int] = field(default_factory=dict)
    # Session duration stats (Welford's online algorithm)
    session_duration_mean: float = 0.0
    session_duration_m2: float = 0.0
    session_count: int = 0
    # Geographic locations seen
    locations_seen: dict[str, int] = field(default_factory=dict)
    # Source IP addresses seen
    source_ips: dict[str, int] = field(default_factory=dict)
    # Custom numeric feature running stats {name: (mean, m2, count)}
    feature_stats: dict[str, tuple[float, float, int]] = field(default_factory=dict)

    @property
    def session_duration_variance(self) -> float:
        if self.session_count < 2:
            return 0.0
        return self.session_duration_m2 / (self.session_count - 1)

    @property
    def session_duration_std(self) -> float:
        return math.sqrt(self.session_duration_variance)

    def hour_probabilities(self) -> np.ndarray:
        total = self.hour_distribution.sum()
        if total == 0:
            return np.ones(24) / 24.0
        return self.hour_distribution / total

    def dow_probabilities(self) -> np.ndarray:
        total = self.dow_distribution.sum()
        if total == 0:
            return np.ones(7) / 7.0
        return self.dow_distribution / total

    def top_resources(self, n: int = 10) -> list[tuple[str, int]]:
        return sorted(
            self.resource_frequencies.items(), key=lambda x: x[1], reverse=True
        )[:n]


class BehavioralBaseline:
    """
    Learns and maintains behavioral baselines for entities.

    Uses online (streaming) statistical methods so baselines can be
    updated incrementally without storing raw event data.
    """

    def __init__(self, decay_factor: float = 0.995):
        self.profiles: dict[str, BaselineProfile] = {}
        self.decay_factor = decay_factor

    def get_or_create_profile(
        self, entity_id: str, entity_type: str = "user"
    ) -> BaselineProfile:
        if entity_id not in self.profiles:
            self.profiles[entity_id] = BaselineProfile(
                entity_id=entity_id, entity_type=entity_type
            )
        return self.profiles[entity_id]

    def observe(self, entity_id: str, event: dict[str, Any]) -> BaselineProfile:
        """
        Update a baseline profile with a new observed event.

        Event dict keys (all optional):
            entity_type, hour (0-23), day_of_week (0-6), resource,
            action, session_duration, location, source_ip,
            features (dict of numeric values)
        """
        entity_type = event.get("entity_type", "user")
        profile = self.get_or_create_profile(entity_id, entity_type)
        profile.observation_count += 1
        profile.updated_at = time.time()

        hour = event.get("hour")
        if hour is not None and 0 <= hour < 24:
            profile.hour_distribution[int(hour)] += 1

        dow = event.get("day_of_week")
        if dow is not None and 0 <= dow < 7:
            profile.dow_distribution[int(dow)] += 1

        resource = event.get("resource")
        if resource:
            profile.resource_frequencies[resource] = (
                profile.resource_frequencies.get(resource, 0) + 1
            )

        action = event.get("action")
        if action:
            profile.action_frequencies[action] = (
                profile.action_frequencies.get(action, 0) + 1
            )

        duration = event.get("session_duration")
        if duration is not None:
            profile.session_count += 1
            delta = duration - profile.session_duration_mean
            profile.session_duration_mean += delta / profile.session_count
            delta2 = duration - profile.session_duration_mean
            profile.session_duration_m2 += delta * delta2

        location = event.get("location")
        if location:
            profile.locations_seen[location] = (
                profile.locations_seen.get(location, 0) + 1
            )

        source_ip = event.get("source_ip")
        if source_ip:
            profile.source_ips[source_ip] = (
                profile.source_ips.get(source_ip, 0) + 1
            )

        features = event.get("features", {})
        for feat_name, feat_val in features.items():
            if feat_name not in profile.feature_stats:
                profile.feature_stats[feat_name] = (0.0, 0.0, 0)
            mean, m2, count = profile.feature_stats[feat_name]
            count += 1
            delta = feat_val - mean
            mean += delta / count
            delta2 = feat_val - mean
            m2 += delta * delta2
            profile.feature_stats[feat_name] = (mean, m2, count)

        return profile

    def observe_batch(
        self, entity_id: str, events: list[dict[str, Any]]
    ) -> BaselineProfile:
        profile = None
        for event in events:
            profile = self.observe(entity_id, event)
        return profile

    def decay_profiles(self) -> None:
        for profile in self.profiles.values():
            profile.hour_distribution *= self.decay_factor
            profile.dow_distribution *= self.decay_factor

    def get_profile(self, entity_id: str) -> BaselineProfile | None:
        return self.profiles.get(entity_id)

    def profile_summary(self, entity_id: str) -> dict[str, Any] | None:
        profile = self.get_profile(entity_id)
        if profile is None:
            return None
        return {
            "entity_id": profile.entity_id,
            "entity_type": profile.entity_type,
            "observation_count": profile.observation_count,
            "peak_hour": int(np.argmax(profile.hour_distribution)),
            "peak_day": int(np.argmax(profile.dow_distribution)),
            "top_resources": profile.top_resources(5),
            "unique_locations": len(profile.locations_seen),
            "unique_ips": len(profile.source_ips),
            "avg_session_duration": round(profile.session_duration_mean, 2),
            "session_duration_std": round(profile.session_duration_std, 2),
        }

    def all_entity_ids(self) -> list[str]:
        return list(self.profiles.keys())
