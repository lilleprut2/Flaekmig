"""Simple workflow manager to order and schedule plugin runs based on recommendations."""
from typing import List
from core.models import Recommendation


def prioritize(recommendations: List[Recommendation]) -> List[Recommendation]:
    """Return recommendations ordered by confidence descending."""
    return sorted(recommendations, key=lambda r: r.confidence, reverse=True)
