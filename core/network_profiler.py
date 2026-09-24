"""Network measurement and classification for adaptive RustScan runs."""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import subprocess
from typing import List, Optional

from core.models import NetworkProfile


class NetworkProfiler:
    """Measure target responsiveness using a small, bounded ICMP probe."""

    def __init__(self, ping_count: int = 5, timeout_seconds: int = 1):
        if ping_count < 1:
            raise ValueError("ping_count must be positive")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.ping_count = ping_count
        self.timeout_seconds = timeout_seconds

    def profile(self, target: str) -> NetworkProfile:
        """Ping a target and return measurements even when the target is unreachable."""
        command = self._ping_command(target)
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=(self.ping_count * self.timeout_seconds) + 2,
            )
            output = completed.stdout or ""
        except (OSError, subprocess.TimeoutExpired) as exc:
            output = str(exc)

        latencies = self._parse_latencies(output)
        loss = self._parse_packet_loss(output, latencies)
        average = sum(latencies) / len(latencies) if latencies else None
        minimum = min(latencies) if latencies else None
        maximum = max(latencies) if latencies else None
        responsive = bool(latencies)
        return NetworkProfile(
            target=target,
            average_latency_ms=average,
            min_latency_ms=minimum,
            max_latency_ms=maximum,
            packet_loss_percent=loss,
            quality=self.classify(average, loss, responsive),
            network_type=self.detect_network_type(target, average, responsive),
            host_responsive=responsive,
            sample_count=self.ping_count,
        )

    def classify(
        self,
        average_latency_ms: Optional[float],
        packet_loss_percent: float,
        responsive: bool = True,
    ) -> str:
        if not responsive or packet_loss_percent >= 100.0:
            return "UNREACHABLE"
        latency = average_latency_ms if average_latency_ms is not None else float("inf")
        if latency <= 20 and packet_loss_percent <= 1:
            return "EXCELLENT"
        if latency <= 80 and packet_loss_percent <= 5:
            return "GOOD"
        if latency <= 200 and packet_loss_percent <= 15:
            return "FAIR"
        return "POOR"

    def detect_network_type(
        self, target: str, average_latency_ms: Optional[float], responsive: bool
    ) -> str:
        """Use conservative heuristics; this is advisory rather than authoritative."""
        try:
            address = ipaddress.ip_address(target)
            if address.is_private or address.is_loopback or address.is_link_local:
                return "LOCAL_LAN"
            return "HIGH_LATENCY_NETWORK" if average_latency_ms and average_latency_ms > 200 else "INTERNET_HOST"
        except ValueError:
            interfaces = self._interface_names()
            if any(name.startswith(("tun", "tap", "wg")) for name in interfaces):
                return "VPN"
            if not responsive:
                return "UNKNOWN"
            return "HIGH_LATENCY_NETWORK" if average_latency_ms and average_latency_ms > 200 else "INTERNET_HOST"

    def _ping_command(self, target: str) -> List[str]:
        if platform.system().lower() == "windows":
            return ["ping", "-n", str(self.ping_count), "-w", str(self.timeout_seconds * 1000), target]
        return ["ping", "-c", str(self.ping_count), "-W", str(self.timeout_seconds), target]

    @staticmethod
    def _parse_latencies(output: str) -> List[float]:
        values = []
        for match in re.finditer(r"(?:time|zeit)[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE):
            values.append(float(match.group(1)))
        return values

    def _parse_packet_loss(self, output: str, latencies: List[float]) -> float:
        match = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet )?(?:loss|verlust)", output, re.IGNORECASE)
        if match:
            return min(100.0, max(0.0, float(match.group(1))))
        return max(0.0, 100.0 * (self.ping_count - len(latencies)) / self.ping_count)

    @staticmethod
    def _interface_names() -> List[str]:
        try:
            return os.listdir("/sys/class/net")
        except OSError:
            return []
