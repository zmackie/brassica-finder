"""Privilege escalation path discovery."""

from .analyzer import analyze_paths
from .knowledge import get_known_techniques, ESCALATION_TECHNIQUES

__all__ = ["analyze_paths", "get_known_techniques", "ESCALATION_TECHNIQUES"]
