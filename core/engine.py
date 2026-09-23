"""Decision engine coordinating plugins and rules."""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union
import shutil
import importlib
import threading
import time
import sys

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
        # merge saved inventory if present
        try:
            saved = self.load_installed_tools_file()
            if saved:
                for k, v in saved.items():
                    live = self.available_binaries.get(k)
                    # prefer live binary path, but merge python flag if missing
                    if isinstance(live, dict) and isinstance(v, dict):
                        if live.get("python") is None and v.get("python") is not None:
                            live["python"] = v.get("python")
                            self.available_binaries[k] = live
                    else:
                        # if live not dict, replace with saved dict
                        self.available_binaries[k] = v
        except Exception:
            pass

    def write_installed_tools_file(self, path: str = "installed_tools.txt"):
        """Write the current available_binaries mapping to a text file (JSON)."""
        import json, os

        # Normalize structure for writing: if value is dict, keep; if None/string, wrap
        out = {}
        for k, v in self.available_binaries.items():
            if isinstance(v, dict):
                out[k] = v
            else:
                out[k] = {"binary": v, "python": None}

        # Write to project root (parent of core/) to keep a single canonical file.
        project_root = os.path.dirname(os.path.dirname(__file__))
        target_path = os.path.join(project_root, path)
        tmp_path = target_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
            try:
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp_path, target_path)
        return target_path

    def load_installed_tools_file(self, path: str = "installed_tools.txt") -> Optional[Dict[str, Dict[str, Optional[str]]]]:
        """Load installed tools JSON if present in cwd and return mapping or None."""
        import os, json

        project_root = os.path.dirname(os.path.dirname(__file__))
        target_path = os.path.join(project_root, path)
        if not os.path.exists(target_path):
            return None
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data
        except Exception:
            return None

    def ensure_tool(self, tool_name: str, attempt_install: bool = False) -> bool:
        """Ensure a tool is installed. If missing, prompt the user to attempt installation.

        Returns True if the tool is available after this call, False otherwise.
        """
        info = self.available_binaries.get(tool_name)
        # info may be dict or simple path
        binary = None
        py_ok = None
        if isinstance(info, dict):
            binary = info.get("binary")
            py_ok = info.get("python")
        else:
            binary = info

        if binary:
            return True

        # If python module available, treat as available
        if py_ok:
            return True

        # If caller didn't request an automatic attempt, prompt user interactively
        if not attempt_install:
            try:
                ans = input(f"Tool '{tool_name}' is not installed. Attempt install? [y/N]: ").strip().lower()
            except Exception:
                return False

            if ans != "y":
                return False

        # Propose platform-specific install commands using a mapping per OS
        import platform, subprocess, shutil

        system = platform.system().lower()

        # per-tool package mapping: logical tool -> {apt:, brew:, pacman:, pip:}
        pkg_map = {
            "nmap": {"apt": "nmap", "brew": "nmap", "pacman": "nmap"},
            "gobuster": {"apt": "gobuster", "brew": "gobuster", "pacman": "gobuster"},
            "nuclei": {"apt": "nuclei", "brew": "nuclei", "pacman": "nuclei"},
            "amass": {"apt": "amass", "brew": "amass", "pacman": "amass"},
            "subfinder": {"apt": "subfinder", "brew": "subfinder", "pacman": "subfinder"},
            "impacket": {"pip": "impacket"},
            "bloodhound-python": {"pip": "bloodhound"},
            "sqlmap": {"apt": "sqlmap", "brew": "sqlmap", "pacman": "sqlmap"},
            # fallback: try installing the tool name as package
        }

        mapping = pkg_map.get(tool_name, {})

        install_cmd = None
        # choose install method based on OS and mapping availability
        if system == "linux":
            # prefer pacman if present (Arch/Manjaro). Do NOT perform a full system
            # upgrade; only install the requested package(s).
            if shutil.which("pacman"):
                pkg = mapping.get("pacman") or mapping.get("apt") or tool_name
                install_cmd = f"sudo pacman -S --noconfirm {pkg}"
            elif shutil.which("apt-get"):
                pkg = mapping.get("apt") or tool_name
                install_cmd = f"sudo apt-get update && sudo apt-get install -y {pkg}"
            else:
                print("No supported package manager found (pacman/apt). Please install the tool manually.")
                return False
        elif system == "darwin":
            # Prefer Homebrew on macOS. If brew isn't present, do not attempt to run
            # a non-existent command; instead, offer a clear manual instruction.
            if shutil.which("brew"):
                pkg = mapping.get("brew") or mapping.get("apt") or tool_name
                install_cmd = f"brew install {pkg}"
            else:
                # If the missing tool is a python package, try pipx/pip as fallback
                if mapping.get("pip"):
                    pkg = mapping.get("pip")
                    if shutil.which("pipx"):
                        install_cmd = f"pipx install {pkg}"
                    else:
                        install_cmd = f"python3 -m pip install --user {pkg}"
                else:
                    print(
                        "Homebrew not found. Automatic install is unavailable on this mac.\n"
                        "Please install Homebrew (https://brew.sh) and then run:"
                        f" brew install {tool_name}"
                    )
                    return False

        # If we still don't have a command but there's a pip mapping, try pip install
        if not install_cmd and mapping.get("pip"):
            pkg = mapping.get("pip")
            # try pipx first if available
            if shutil.which("pipx"):
                install_cmd = f"pipx install {pkg}"
            else:
                install_cmd = f"python3 -m pip install --user {pkg}"

        if not install_cmd:
            print("Automatic install is not supported for this tool on this platform. Please install manually.")
            return False

        try:
            print(f"Running: {install_cmd}")
            subprocess.run(install_cmd, shell=True, check=True)
        except subprocess.CalledProcessError:
            print("Install command failed or requires manual steps.")
            return False

        # Re-detect this binary
        new_map = self.detect_binaries([tool_name])
        # merge into available_binaries
        self.available_binaries[tool_name] = new_map.get(tool_name)
        # persist
        try:
            self.write_installed_tools_file()
        except Exception:
            pass

        # return True if now present
        info2 = self.available_binaries.get(tool_name)
        if isinstance(info2, dict):
            return bool(info2.get("binary")) or bool(info2.get("python"))
        return bool(info2)

    def register_plugin(self, plugin: Plugin):
        self.plugins[plugin.name] = plugin
        # detect plugin-specific binary presence and cache
        rb = getattr(plugin, "required_binary", None)
        if rb:
            path = shutil.which(rb)
            # store standardized dict
            self.available_binaries[rb] = {"binary": path, "python": None}

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
                info = self.available_binaries.get(rb)
                present = False
                if isinstance(info, dict):
                    present = bool(info.get("binary")) or bool(info.get("python"))
                else:
                    present = bool(info)

                if not present:
                    # prompt to install via ensure_tool; skip if declined
                    ok = self.ensure_tool(rb)
                    if not ok:
                        continue

            # Run plugin in a background thread so we can show a progress spinner.
            result_container: Dict[str, ScanResult] = {}

            def _runner():
                try:
                    result_container["res"] = p.run(target_obj)
                except Exception as e:
                    result_container["res"] = ScanResult(plugin=p.name, target=target_obj, raw=str(e))

            thread = threading.Thread(target=_runner, daemon=True)
            thread.start()

            spinner = "|/-\\"
            idx = 0
            # Print initial message
            sys.stdout.write(f"Running {p.name} ")
            sys.stdout.flush()
            while thread.is_alive():
                sys.stdout.write(spinner[idx % len(spinner)])
                sys.stdout.flush()
                time.sleep(0.12)
                sys.stdout.write("\b")
                idx += 1

            thread.join()
            sys.stdout.write(" Done\n")
            sys.stdout.flush()

            res = result_container.get("res")
            if res is None:
                # If nothing returned, create a placeholder
                res = ScanResult(plugin=p.name, target=target_obj, raw="No result")
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
        """Detect common security tool binaries on PATH and try Python import checks.

        Returns a mapping of tool -> dict with keys:
        - `binary`: path or None
        - `python`: True/False/None (None means not applicable)
        """
        # Map logical names -> probes and optional python module names
        tool_map = {
            "nmap": {"bins": ["nmap"]},
            "rustscan": {"bins": ["rustscan"]},
            "masscan": {"bins": ["masscan"]},
            "httpx": {"bins": ["httpx"]},
            "amass": {"bins": ["amass"]},
            "subfinder": {"bins": ["subfinder"]},
            "dnsx": {"bins": ["dnsx"]},
            "whatweb": {"bins": ["whatweb"]},
            "ffuf": {"bins": ["ffuf"]},
            "gobuster": {"bins": ["gobuster"]},
            "katana": {"bins": ["katana"]},
            "nuclei": {"bins": ["nuclei"]},
            "nikto": {"bins": ["nikto"]},
            "sqlmap": {"bins": ["sqlmap"]},
            "wpscan": {"bins": ["wpscan"]},
            "enum4linux-ng": {"bins": ["enum4linux-ng", "enum4linux"]},
            "smbmap": {"bins": ["smbmap"]},
            "netexec": {"bins": ["netexec"]},
            "bloodhound-python": {"bins": ["bloodhound-python", "bloodhound"], "py": ["bloodhound"]},
            "kerbrute": {"bins": ["kerbrute"]},
            "impacket": {"py": ["impacket"]},
            "searchsploit": {"bins": ["searchsploit"]},
            "metasploit": {"bins": ["msfconsole", "msfvenom"]},
            "trivy": {"bins": ["trivy"]},
            "scoutsuite": {"bins": ["scoutsuite", "ScoutSuite"]},
        }

        keys = tools if tools is not None else list(tool_map.keys())
        result: Dict[str, Dict[str, Optional[str]]] = {}
        for key in keys:
            entry = tool_map.get(key, {"bins": [key]})
            bins = entry.get("bins", [])
            pymods = entry.get("py", [])

            found_bin = None
            for probe in bins:
                # simple glob handling
                if probe.endswith("*"):
                    prefix = probe[:-1]
                    p = shutil.which(prefix)
                else:
                    p = shutil.which(probe)
                if p:
                    found_bin = p
                    break

            py_available = None
            if pymods:
                for mod in pymods:
                    try:
                        __import__(mod)
                        py_available = True
                        break
                    except Exception:
                        py_available = False

            result[key] = {"binary": found_bin, "python": py_available}

        return result
