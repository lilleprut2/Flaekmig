"""Decision engine coordinating plugins and rules."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
import shutil
import importlib

from core.models import Target, ScanResult, Recommendation, Plugin
from core.rules import default_rules, Rule


@dataclass
class EngineResult:
    scan_results: List[ScanResult]
    recommendations: List[Recommendation]


class Engine:
    def __init__(self):
        self.plugins: Dict[str, Plugin] = {}
        self.rules: List[Rule] = default_rules()
        # map of binary name -> absolute path or None
        self.available_binaries: Dict[str, Optional[str]] = self.detect_binaries()

    def register_plugin(self, plugin: Plugin):
        self.plugins[plugin.name] = plugin
        # detect plugin-specific binary presence and cache
        rb = getattr(plugin, "required_binary", None)
        if rb:
            self.available_binaries[rb] = shutil.which(rb)

    def load_plugins_from_package(self, package: str = "plugins"):
        # naive loader: expects each plugin package to expose `plugin` name
        # kept minimal to avoid heavy dependency on importlib.metadata
        # In future, support entry points or config.
        pass

    def run_target(self, target: Union[str, Target], plugin_names: Optional[List[str]] = None) -> EngineResult:
        # Accept either a string or a Target instance. If string, classify it.
        if isinstance(target, str):
            target_obj = Target.from_string(target)
        else:
            target_obj = target
        scan_results: List[ScanResult] = []

        # choose plugins
        if plugin_names:
            chosen = [self.plugins[n] for n in plugin_names if n in self.plugins]
        else:
            chosen = list(self.plugins.values())

        for p in chosen:
            # check binary availability when declared, consult cached map
            rb = getattr(p, "required_binary", None)
            if rb is not None:
                if not self.available_binaries.get(rb):
                    # skip if binary missing; plugins may still implement simulated logic
                    continue
            try:
                res = p.run(target_obj)
            except Exception as e:
                # plugin failure shouldn't stop engine; add lightweight record
                res = ScanResult(plugin=p.name, target=target_obj, raw=str(e))
            scan_results.append(res)

        # evaluate rules against aggregated scan outputs
        recommendations: List[Recommendation] = []
        for rule in self.rules:
            for res in scan_results:
                recs = rule.evaluate(res)
                recommendations.extend(recs)

        # deduplicate by tool and pick max confidence
        dedup: Dict[str, Recommendation] = {}
        for r in recommendations:
            if r.tool not in dedup or r.confidence > dedup[r.tool].confidence:
                dedup[r.tool] = r

        return EngineResult(scan_results=scan_results, recommendations=list(dedup.values()))

    def detect_binaries(self, tools: Optional[List[str]] = None) -> Dict[str, Optional[str]]:
        """Detect common security tool binaries on PATH and return a mapping.

        This runs at Engine initialization so the app knows which integrations
        are available on the host. The list can be customized by passing
        `tools` or by calling `register_plugin()` which will check plugin binaries.
        """
        # Map logical tool names to possible binaries to look for on PATH.
        tool_map = {
            "nmap": ["nmap"],
            "rustscan": ["rustscan"],
            "masscan": ["masscan"],
            "httpx": ["httpx"],
            "amass": ["amass"],
            "subfinder": ["subfinder"],
            "dnsx": ["dnsx"],
            "whatweb": ["whatweb"],
            "ffuf": ["ffuf"],
            "gobuster": ["gobuster"],
            "katana": ["katana"],
            "nuclei": ["nuclei"],
            "nikto": ["nikto"],
            "sqlmap": ["sqlmap"],
            "wpscan": ["wpscan"],
            "enum4linux-ng": ["enum4linux-ng", "enum4linux"],
            "smbmap": ["smbmap"],
            "netexec": ["netexec"],
            "bloodhound-python": ["bloodhound-python", "bloodhound"],
            "kerbrute": ["kerbrute"],
            "impacket": ["impacket-*"] ,
            "searchsploit": ["searchsploit"],
            "metasploit": ["msfconsole", "msfvenom"],
            "trivy": ["trivy"],
            "scoutsuite": ["scoutsuite", "ScoutSuite"],
        }

        # If a custom list was provided, prefer it (strings of tool keys).
        keys = tools if tools is not None else list(tool_map.keys())
        found: Dict[str, Optional[str]] = {}
        for key in keys:
            probes = tool_map.get(key, [key])
            found_path = None
            for probe in probes:
                # Support simple glob-like entries (impacket-*) by checking prefix
                if probe.endswith("*"):
                    prefix = probe[:-1]
                    # try to find any matching executable on PATH
                    # naive approach: check a few common names, else skip
                    # we fallback to shutil.which of the prefix itself
                    p = shutil.which(prefix)
                else:
                    p = shutil.which(probe)
                if p:
                    found_path = p
                    break
            found[key] = found_path
        return found
