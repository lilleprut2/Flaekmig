"""Minimal Nmap plugin for Flaekmig."""
from __future__ import annotations
from typing import List
import shutil
import subprocess
import re

from core.models import Plugin, Target, ScanResult, PortInfo


class NmapPlugin:
    name = "nmap"
    description = "Performs TCP port discovery using nmap (greppable output)."
    required_binary = "nmap"
    supported_targets = ["host", "cidr"]

    def run(self, target: Target) -> ScanResult:
        if shutil.which(self.required_binary) is None:
            raise RuntimeError("nmap binary not found")

        # minimal, non-invasive default flags
        cmd = ["nmap", "-sS", "-p-", "-oG", "-", target.host]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out = proc.stdout if proc.returncode == 0 else proc.stderr
        return self.parse(out)

    def parse(self, output: str) -> ScanResult:
        # parse nmap greppable lines: Ports: 22/open/tcp//ssh///
        ports: List[PortInfo] = []
        for line in output.splitlines():
            if "Ports:" in line:
                m = re.search(r"Ports:\s*(.*)", line)
                if not m:
                    continue
                parts = m.group(1).split(',')
                for part in parts:
                    # each part like '22/open/tcp//ssh//'
                    fields = part.split('/')
                    try:
                        port = int(fields[0])
                        state = fields[1]
                        proto = fields[2]
                        ports.append(PortInfo(port=port, proto=proto, state=state))
                    except Exception:
                        continue

        return ScanResult(plugin=self.name, target=Target(host=""), raw=output, ports=ports)
