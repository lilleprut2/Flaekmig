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
class ScanResult:
    plugin: str
    target: Target
    raw: str
    ports: List[PortInfo] = field(default_factory=list)
    services: Dict[str, Any] = field(default_factory=dict)


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
