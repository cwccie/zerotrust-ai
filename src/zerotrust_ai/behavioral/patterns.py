"""
Pattern analysis for behavioral analytics.

Detects temporal patterns, frequency anomalies, and behavioral
clustering across entity populations.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from .baseline import BehavioralBaseline


class PatternAnalyzer:
    """Analyzes behavioral patterns across entity populations."""

    def __init__(self, baseline_engine: BehavioralBaseline | None = None):
        self.baseline = baseline_engine or BehavioralBaseline()

    def detect_time_anomaly(
        self, entity_id: str, hour: int, day_of_week: int
    ) -> dict[str, Any]:
        """Check if access at given time is anomalous for entity."""
        profile = self.baseline.get_profile(entity_id)
        if profile is None or profile.observation_count < 10:
            return {"anomalous": False, "reason": "insufficient_data"}

        hour_probs = profile.hour_probabilities()
        dow_probs = profile.dow_probabilities()

        hour_score = 1.0 - (hour_probs[hour] / max(hour_probs.max(), 1e-10))
        dow_score = 1.0 - (dow_probs[day_of_week] / max(dow_probs.max(), 1e-10))

        combined = 0.6 * hour_score + 0.4 * dow_score

        return {
            "anomalous": combined > 0.7,
            "score": round(combined, 4),
            "hour_score": round(hour_score, 4),
            "dow_score": round(dow_score, 4),
            "expected_peak_hour": int(np.argmax(hour_probs)),
            "expected_peak_day": int(np.argmax(dow_probs)),
        }

    def detect_geographic_anomaly(
        self, entity_id: str, location: str
    ) -> dict[str, Any]:
        """Check if a location is anomalous for an entity."""
        profile = self.baseline.get_profile(entity_id)
        if profile is None:
            return {"anomalous": False, "reason": "no_profile"}

        if location not in profile.locations_seen:
            return {
                "anomalous": True,
                "score": 0.9,
                "reason": "never_seen_location",
                "known_locations": list(profile.locations_seen.keys()),
            }

        total = sum(profile.locations_seen.values())
        freq = profile.locations_seen[location] / total if total > 0 else 0
        score = max(0.0, 1.0 - freq * 5)

        return {
            "anomalous": score > 0.7,
            "score": round(score, 4),
            "visit_count": profile.locations_seen[location],
            "frequency": round(freq, 4),
        }

    def population_outliers(
        self, feature: str = "observation_count", z_threshold: float = 2.5
    ) -> list[dict[str, Any]]:
        """Find entities that are statistical outliers in the population."""
        values = []
        ids = []
        for eid, profile in self.baseline.profiles.items():
            if feature == "observation_count":
                values.append(profile.observation_count)
            elif feature == "unique_resources":
                values.append(len(profile.resource_frequencies))
            elif feature == "unique_locations":
                values.append(len(profile.locations_seen))
            elif feature == "unique_ips":
                values.append(len(profile.source_ips))
            else:
                continue
            ids.append(eid)

        if len(values) < 3:
            return []

        arr = np.array(values, dtype=np.float64)
        mean = arr.mean()
        std = arr.std()
        if std == 0:
            return []

        outliers = []
        for i, (eid, val) in enumerate(zip(ids, values)):
            z = abs(val - mean) / std
            if z > z_threshold:
                outliers.append({
                    "entity_id": eid,
                    "feature": feature,
                    "value": val,
                    "z_score": round(z, 4),
                    "population_mean": round(mean, 2),
                    "population_std": round(std, 2),
                })

        return sorted(outliers, key=lambda x: x["z_score"], reverse=True)

    def entropy_score(self, entity_id: str) -> dict[str, float]:
        """Calculate entropy of various behavioral distributions."""
        profile = self.baseline.get_profile(entity_id)
        if profile is None:
            return {}

        result = {}

        # Hour entropy
        hp = profile.hour_probabilities()
        hp_nonzero = hp[hp > 0]
        result["hour_entropy"] = round(
            float(-np.sum(hp_nonzero * np.log2(hp_nonzero))), 4
        )

        # Resource entropy
        total_res = sum(profile.resource_frequencies.values())
        if total_res > 0:
            res_probs = np.array(
                list(profile.resource_frequencies.values()), dtype=np.float64
            ) / total_res
            res_nonzero = res_probs[res_probs > 0]
            result["resource_entropy"] = round(
                float(-np.sum(res_nonzero * np.log2(res_nonzero))), 4
            )

        return result
