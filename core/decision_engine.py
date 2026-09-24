"""Decision facade for network profiling and RustScan optimization."""
from __future__ import annotations

from core.models import NetworkProfile, RustScanConfig
from core.network_profiler import NetworkProfiler
from core.rustscan_optimizer import OptimizationDecision, RustScanOptimizer


class DecisionEngine:
    """Coordinate measurement and configuration selection for a target."""

    def __init__(self, profiler: NetworkProfiler, optimizer: RustScanOptimizer):
        self.profiler = profiler
        self.optimizer = optimizer

    def decide(self, target: str) -> tuple[NetworkProfile, OptimizationDecision]:
        profile = self.profiler.profile(target)
        return profile, self.optimizer.select_config(profile, target)

    def choose_config(self, target: str) -> RustScanConfig:
        return self.decide(target)[1].config
