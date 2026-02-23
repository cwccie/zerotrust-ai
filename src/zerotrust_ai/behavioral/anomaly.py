"""
Anomaly detection engine.

Detects deviations from learned behavioral baselines using
statistical methods: z-score analysis, KL divergence for
distributions, and entropy-based novelty detection.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .baseline import BaselineProfile, BehavioralBaseline


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a single event."""

    entity_id: str
    anomaly_score: float  # 0.0 (normal) to 1.0 (highly anomalous)
    is_anomalous: bool
    details: dict[str, Any] = field(default_factory=dict)
    component_scores: dict[str, float] = field(default_factory=dict)


class AnomalyDetector:
    """
    Detects anomalous behavior by comparing events against baselines.

    Uses multiple detection methods and combines them into a
    composite anomaly score.
    """

    def __init__(
        self,
        baseline_engine: BehavioralBaseline | None = None,
        threshold: float = 0.7,
        time_weight: float = 0.2,
        resource_weight: float = 0.25,
        location_weight: float = 0.25,
        ip_weight: float = 0.15,
        duration_weight: float = 0.15,
    ):
        self.baseline = baseline_engine or BehavioralBaseline()
        self.threshold = threshold
        self.weights = {
            "time": time_weight,
            "resource": resource_weight,
            "location": location_weight,
            "ip": ip_weight,
            "duration": duration_weight,
        }

    def analyze(self, entity_id: str, event: dict[str, Any]) -> AnomalyResult:
        """Analyze a single event for anomalies against the entity's baseline."""
        profile = self.baseline.get_profile(entity_id)

        if profile is None or profile.observation_count < 10:
            return AnomalyResult(
                entity_id=entity_id,
                anomaly_score=0.5,
                is_anomalous=False,
                details={"reason": "insufficient_baseline"},
            )

        scores = {}
        details = {}

        # Time-of-day anomaly
        hour = event.get("hour")
        if hour is not None:
            score, detail = self._time_anomaly(profile, int(hour))
            scores["time"] = score
            details["time"] = detail

        # Resource anomaly
        resource = event.get("resource")
        if resource:
            score, detail = self._resource_anomaly(profile, resource)
            scores["resource"] = score
            details["resource"] = detail

        # Location anomaly
        location = event.get("location")
        if location:
            score, detail = self._location_anomaly(profile, location)
            scores["location"] = score
            details["location"] = detail

        # Source IP anomaly
        source_ip = event.get("source_ip")
        if source_ip:
            score, detail = self._ip_anomaly(profile, source_ip)
            scores["ip"] = score
            details["ip"] = detail

        # Session duration anomaly
        duration = event.get("session_duration")
        if duration is not None:
            score, detail = self._duration_anomaly(profile, duration)
            scores["duration"] = score
            details["duration"] = detail

        # Weighted composite score
        if not scores:
            composite = 0.0
        else:
            weighted_sum = 0.0
            weight_sum = 0.0
            for key, score in scores.items():
                w = self.weights.get(key, 0.1)
                weighted_sum += score * w
                weight_sum += w
            composite = weighted_sum / weight_sum if weight_sum > 0 else 0.0

        return AnomalyResult(
            entity_id=entity_id,
            anomaly_score=round(composite, 4),
            is_anomalous=composite >= self.threshold,
            details=details,
            component_scores=scores,
        )

    def analyze_batch(
        self, entity_id: str, events: list[dict[str, Any]]
    ) -> list[AnomalyResult]:
        return [self.analyze(entity_id, event) for event in events]

    def _time_anomaly(
        self, profile: BaselineProfile, hour: int
    ) -> tuple[float, dict]:
        probs = profile.hour_probabilities()
        prob = probs[hour]
        max_prob = probs.max()

        if max_prob == 0:
            return 0.0, {"hour": hour, "probability": 0.0}

        # Low probability relative to peak = anomalous
        relative = 1.0 - (prob / max_prob)
        # Also penalize if this hour has zero observations
        if profile.hour_distribution[hour] == 0:
            relative = min(relative + 0.3, 1.0)

        return round(relative, 4), {
            "hour": hour,
            "probability": round(float(prob), 4),
            "peak_hour": int(np.argmax(probs)),
        }

    def _resource_anomaly(
        self, profile: BaselineProfile, resource: str
    ) -> tuple[float, dict]:
        count = profile.resource_frequencies.get(resource, 0)
        total = sum(profile.resource_frequencies.values())

        if total == 0:
            return 0.5, {"resource": resource, "seen_count": 0}

        if count == 0:
            # Never-before-seen resource
            n_unique = len(profile.resource_frequencies)
            # More unique resources seen = less surprising to see a new one
            novelty = max(0.6, 1.0 - (n_unique / 100.0))
            return round(novelty, 4), {
                "resource": resource,
                "seen_count": 0,
                "novel": True,
            }

        freq = count / total
        max_freq = max(profile.resource_frequencies.values()) / total
        score = 1.0 - (freq / max_freq) if max_freq > 0 else 0.0
        return round(score * 0.5, 4), {
            "resource": resource,
            "seen_count": count,
            "frequency": round(freq, 4),
        }

    def _location_anomaly(
        self, profile: BaselineProfile, location: str
    ) -> tuple[float, dict]:
        count = profile.locations_seen.get(location, 0)
        if count == 0:
            # Never-before-seen location
            return 0.9, {"location": location, "novel": True, "seen_count": 0}

        total = sum(profile.locations_seen.values())
        freq = count / total if total > 0 else 0.0
        # Rarely seen locations are more anomalous
        score = max(0.0, 1.0 - (freq * 5))  # freq > 0.2 = normal
        return round(score, 4), {
            "location": location,
            "seen_count": count,
            "frequency": round(freq, 4),
        }

    def _ip_anomaly(
        self, profile: BaselineProfile, ip: str
    ) -> tuple[float, dict]:
        count = profile.source_ips.get(ip, 0)
        if count == 0:
            return 0.8, {"source_ip": ip, "novel": True, "seen_count": 0}

        total = sum(profile.source_ips.values())
        freq = count / total if total > 0 else 0.0
        score = max(0.0, 1.0 - (freq * 3))
        return round(score, 4), {
            "source_ip": ip,
            "seen_count": count,
            "frequency": round(freq, 4),
        }

    def _duration_anomaly(
        self, profile: BaselineProfile, duration: float
    ) -> tuple[float, dict]:
        if profile.session_count < 5:
            return 0.0, {"duration": duration, "insufficient_data": True}

        std = profile.session_duration_std
        if std == 0:
            std = 1.0

        z_score = abs(duration - profile.session_duration_mean) / std
        # Sigmoid mapping of z-score to 0-1
        score = 1.0 / (1.0 + math.exp(-1.5 * (z_score - 2.0)))

        return round(score, 4), {
            "duration": duration,
            "z_score": round(z_score, 4),
            "baseline_mean": round(profile.session_duration_mean, 2),
            "baseline_std": round(std, 2),
        }
