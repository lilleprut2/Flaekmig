"""Adaptive RustScan configuration selection."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from statistics import median
from typing import Dict, Iterable, Optional, Tuple

from core.models import NetworkProfile, RustScanConfig
from core.statistics import ScanHistoryManager, ScanHistoryRecord

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class OptimizationDecision:
    config: RustScanConfig
    reason: str
    history_count: int


class RustScanOptimizer:
    """Choose a safe baseline and cautiously adapt it from observed scan history."""

    BASELINES: Dict[str, Tuple[int, int]] = {
        "EXCELLENT": (10000, 1000),
        "GOOD": (7500, 1500),
        "FAIR": (5000, 2500),
        "POOR": (2000, 5000),
        "UNREACHABLE": (1000, 8000),
    }

    def __init__(self, history: Optional[ScanHistoryManager] = None, minimum_history: int = 10):
        self.history = history
        self.minimum_history = minimum_history
        if minimum_history < 1:
            raise ValueError("minimum_history must be positive")

    def select_config(self, profile: NetworkProfile, target: Optional[str] = None) -> OptimizationDecision:
        batch_size, timeout_ms = self.BASELINES.get(profile.quality, self.BASELINES["FAIR"])
        records = self._history_for(target or profile.target)
        if len(records) < self.minimum_history:
            return OptimizationDecision(
                RustScanConfig(batch_size=batch_size, timeout_ms=timeout_ms),
                f"baseline for {profile.quality} network",
                len(records),
            )

        adapted_batch, adapted_timeout, reason = self._learn(records, batch_size, timeout_ms)
        return OptimizationDecision(
            RustScanConfig(batch_size=adapted_batch, timeout_ms=adapted_timeout),
            reason,
            len(records),
        )

    def _history_for(self, target: str) -> list[ScanHistoryRecord]:
        if self.history is None:
            return []
        try:
            return self.history.recent(target=target, limit=100)
        except Exception:
            LOGGER.exception("Unable to read RustScan history")
            return []

    def _learn(self, records: Iterable[ScanHistoryRecord], baseline_batch: int, baseline_timeout: int) -> Tuple[int, int, str]:
        records = list(records)
        recent = records[: min(20, len(records))]
        best = max(recent, key=lambda item: item.score)
        median_loss = median(item.packet_loss for item in recent)
        median_ports = median(item.open_ports_found for item in recent)
        median_duration = median(item.scan_duration for item in recent)

        if median_loss > 10 or best.packet_loss > 20:
            reduced = max(1000, int(min(baseline_batch, best.batch_size) * 0.75))
            timeout = max(baseline_timeout, int(best.timeout * 1.25))
            return reduced, timeout, "reduced aggressiveness due to packet loss"

        if best.open_ports_found < median_ports or best.scan_duration > median_duration * 2:
            return baseline_batch, baseline_timeout, "baseline retained because history is inconsistent"

        increased = min(10000, max(baseline_batch, int(best.batch_size * 1.10)))
        timeout = max(500, int(baseline_timeout * (0.9 if increased > baseline_batch else 1.0)))
        return increased, timeout, "increased aggressiveness from high-scoring history"
