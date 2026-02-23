"""Lateral movement detection for ZeroTrust-AI."""

from .detector import LateralMovementDetector
from .graph import AccessGraph

__all__ = ["LateralMovementDetector", "AccessGraph"]
