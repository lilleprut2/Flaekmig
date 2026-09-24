"""Core data models and plugin interface for Flaekmig."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Protocol
import ipaddress
from urllib.parse import urlparse


@dataclass
class Target:
    host: str
    meta: Dict[str, Any] = field(default_factory=dict)
    kind: str = "host"  # one of: host, ip, cidr, url

    @classmethod
    def from_string(cls, s: str) -> "Target":
        """Create a Target and heuristically determine whether input is an IP, CIDR, URL, or hostname."""
        s = s.strip()
        # Try CIDR / IP
        try:
            if "/" in s:
                ipaddress.ip_network(s, strict=False)
                return cls(host=s, kind="cidr")
            else:
                ipaddress.ip_address(s)
                return cls(host=s, kind="ip")
        except Exception:
            pass

        # Try URL
        try:
            parsed = urlparse(s if "//" in s else f"//{s}")
            # If parsed.netloc or parsed.path contains a hostname
            hostname = parsed.hostname
            if hostname:
                return cls(host=hostname, kind="url")
        except Exception:
            pass

        # Fallback to hostname
        return cls(host=s, kind="host")


@dataclass
class PortInfo:
    port: int
    proto: str = "tcp"
    state: str = "open"


@dataclass
class NetworkProfile:
    """Measured network conditions used to choose a scan strategy."""

    target: str
    average_latency_ms: Optional[float]
    min_latency_ms: Optional[float]
    max_latency_ms: Optional[float]
    packet_loss_percent: float
    quality: str
    network_type: str = "unknown"
    host_responsive: bool = False
    sample_count: int = 5


@dataclass
class RustScanConfig:
    """RustScan execution settings selected by the optimizer."""

    batch_size: int
    timeout_ms: int
    ulimit: int = 5000
    ports: str = "1-65535"
    nmap_args: List[str] = field(default_factory=lambda: ["-sV"])


@dataclass
class ScanResult:
    plugin: str
    target: Target
    raw: str
    ports: List[PortInfo] = field(default_factory=list)
    services: Dict[str, Any] = field(default_factory=dict)
    scan_duration_seconds: Optional[float] = None
    open_ports_found: Optional[int] = None
    network_quality: Optional[str] = None
    packet_loss_percent: Optional[float] = None
    average_latency_ms: Optional[float] = None
    config: Optional[RustScanConfig] = None


@dataclass
class Recommendation:
    tool: str
    reason: str
    confidence: float


class Plugin(Protocol):
    name: str
    description: str
    required_binary: Optional[str]
    supported_targets: List[str]

    def run(self, target: Target) -> ScanResult:
        ...

    def parse(self, output: str) -> ScanResult:
        ...
