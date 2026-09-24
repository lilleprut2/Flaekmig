"""Adaptive RustScan plugin for Flaekmig."""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from typing import Callable, Optional

from core.decision_engine import DecisionEngine
from core.models import Plugin, ScanResult, Target
from core.network_profiler import NetworkProfiler
from core.rustscan_optimizer import RustScanOptimizer
from core.statistics import ScanHistoryManager

LOGGER = logging.getLogger(__name__)


class RustScanPlugin:
    name = "rustscan"
    description = "Adaptive RustScan port discovery with network profiling and history."
    required_binary = "rustscan"
    supported_targets = ["host", "ip", "cidr"]

    def __init__(
        self,
        profiler: Optional[NetworkProfiler] = None,
        history: Optional[ScanHistoryManager] = None,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    ):
        self.history = history or ScanHistoryManager()
        self.profiler = profiler or NetworkProfiler()
        self.optimizer = RustScanOptimizer(self.history)
        self.decisions = DecisionEngine(self.profiler, self.optimizer)
        self.runner = runner

    def run(self, target: Target) -> ScanResult:
        if shutil.which(self.required_binary) is None:
            raise RuntimeError("rustscan binary not found")

        started = time.monotonic()
        profile, decision = self.decisions.decide(target.host)
        config = decision.config
        command = self.build_command(target, config)
        LOGGER.info("Running adaptive RustScan: %s", command)
        completed = self.runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        duration = time.monotonic() - started
        raw = completed.stdout or ""
        result = self.parse(raw, target)
        result.scan_duration_seconds = duration
        result.open_ports_found = len(result.ports)
        result.network_quality = profile.quality
        result.packet_loss_percent = profile.packet_loss_percent
        result.average_latency_ms = profile.average_latency_ms
        result.config = config
        self.history.record_scan(
            target=target.host,
            latency=profile.average_latency_ms,
            packet_loss=profile.packet_loss_percent,
            batch_size=config.batch_size,
            timeout=config.timeout_ms,
            scan_duration=duration,
            open_ports_found=len(result.ports),
            network_quality=profile.quality,
            network_type=profile.network_type,
        )
        return result

    @staticmethod
    def build_command(target: Target, config) -> list[str]:
        port_option = "--range" if "-" in config.ports else "-p"
        command = [
            "rustscan",
            "-a", target.host,
            "--batch-size", str(config.batch_size),
            "--timeout", str(config.timeout_ms),
            "--ulimit", str(config.ulimit),
            port_option, config.ports,
            "--",
        ]
        return command + list(config.nmap_args)

    def parse(self, output: str, target: Optional[Target] = None) -> ScanResult:
        target = target or Target(host="")
        ports = []
        for line in output.splitlines():
            match = re.search(
                r"\bopen\s+(\d{1,5})/tcp\b|\b(\d{1,5})/tcp\s+open\b|\b(\d{1,5})\s+open\b",
                line,
                re.IGNORECASE,
            )
            if match:
                from core.models import PortInfo
                port = int(next(value for value in match.groups() if value is not None))
                if not any(item.port == port for item in ports):
                    ports.append(PortInfo(port=port))
        return ScanResult(plugin=self.name, target=target, raw=output, ports=ports)

    def close(self) -> None:
        self.history.close()
