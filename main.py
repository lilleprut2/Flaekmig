#!/usr/bin/env python3
"""Flaekmig CLI entrypoint (minimal)."""
import argparse
import json
import queue
import re
import shutil
import sys
import threading
import time
from core.engine import Engine
from plugins.nmap.plugin import NmapPlugin


RUSTSCAN_STALL_TIMEOUT_SECONDS = 300


class ProgressSpinner:
    """Show a lightweight animation while a blocking operation is running."""

    def __init__(self, message):
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def _animate(self):
        frames = "|/-\\"
        frame = 0
        while not self._stop.is_set():
            sys.stderr.write(f"\r{self.message} {frames[frame % len(frames)]}")
            sys.stderr.flush()
            frame += 1
            self._stop.wait(0.12)

    def __enter__(self):
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._stop.set()
        if self._thread:
            self._thread.join()
        sys.stderr.write(f"\r{self.message} Done\n")
        sys.stderr.flush()


def parse_discovery_services(path):
    """Read service names and product/version details from JSON or nmap -oN output."""
    with open(path, "r", encoding="utf-8") as discovery_file:
        text = discovery_file.read()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    services = []
    if isinstance(data, dict):
        for host in data.get("hosts") or []:
            for port in host.get("ports") or []:
                service = port.get("service") or {}
                name = service.get("name") or port.get("service_name")
                product = service.get("product") or ""
                version = service.get("version") or ""
                detail = " ".join(part for part in (product, version) if part).strip()
                if name:
                    services.append((name, detail))
        return services

    # nmap -oN inserts a reason column between SERVICE and VERSION, e.g.
    # "21/tcp open ftp syn-ack vsftpd 2.3.4".
    reason_tokens = {
        "syn-ack", "conn-refused", "no-response", "reset",
        "admin-prohibited", "host-unreach", "port-unreach",
    }
    for line in text.splitlines():
        match = re.match(r"^\s*\d+/tcp\s+open\s+(\S+)(?:\s+(.*))?$", line)
        if not match:
            continue
        name, remainder = match.groups()
        detail = (remainder or "").strip()
        parts = detail.split(None, 1)
        if parts and parts[0].lower() in reason_tokens:
            detail = parts[1] if len(parts) > 1 else ""
        services.append((name, detail))
    return services


def has_msf_module_results(output):
    """Return whether msfconsole output contains at least one module row."""
    plain_output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output or "")
    return any(re.match(r"^\s*\d+\s+\S+", line) for line in plain_output.splitlines())


def has_msf_exploit_results(output):
    """Return whether msfconsole output contains an exploit module row."""
    plain_output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output or "")
    return any(re.match(r"^\s*\d+\s+exploit/\S+", line) for line in plain_output.splitlines())


def has_version_number(detail):
    """Return whether service details contain a numeric dotted version."""
    return bool(re.search(r"\b\d+(?:\.\d+)+(?:[a-zA-Z]+\d*)?\b", detail or ""))


def write_empty_discovery_report(path, target):
    """Write a valid Nmap-style report when RustScan found no ports to inspect."""
    with open(path, "w", encoding="utf-8") as discovery_file:
        discovery_file.write(f"# RustScan scan report for {target}\n")
        discovery_file.write(f"Nmap scan report for {target}\n")
        discovery_file.write("Host is up.\n\n")
        discovery_file.write("PORT STATE SERVICE VERSION\n")
        discovery_file.write(f"# No open ports found for {target}\n")


def build_adaptive_rustscan_command(
    target_ip, history=None, profiler=None, optimizer=None, rust_bin=None, output_path="discovery.json"
):
    """Profile the target and build a rustscan command tuned to the measured network quality."""
    import os

    from core.network_profiler import NetworkProfiler
    from core.rustscan_optimizer import RustScanOptimizer
    from core.statistics import ScanHistoryManager

    history = history or ScanHistoryManager()
    profiler = profiler or NetworkProfiler()
    optimizer = optimizer or RustScanOptimizer(history)
    output_path = os.path.abspath(output_path)

    profile = profiler.profile(target_ip)
    decision = optimizer.select_config(profile, target_ip)
    config = decision.config

    exe = shutil.which("rustscan") or rust_bin
    if not exe:
        raise FileNotFoundError("rustscan executable not found")

    port_option = "--range" if "-" in config.ports else "-p"
    command = [
        exe,
        "-a",
        target_ip,
        "--batch-size",
        str(config.batch_size),
        "--timeout",
        str(config.timeout_ms),
        "--ulimit",
        str(config.ulimit),
        port_option,
        config.ports,
        "--",
        "-sV",
        "-oN",
        output_path,
    ]
    return profile, decision, command


def main():
    parser = argparse.ArgumentParser(prog="flaekmig")
    parser.add_argument("target", nargs="?", help="Target hostname or CIDR (optional for --doctor)")
    parser.add_argument("--plugins", nargs="*", help="Optional plugins to run (by name)")
    parser.add_argument("--doctor", action="store_true", help="Run environment/tools health check and exit")
    parser.add_argument("--yes", action="store_true", help="Automatically say yes to install prompts (non-interactive)")
    parser.add_argument("-ip", "--ip", dest="ip", help="Run rustscan against an IPv4 address and save results to Discovery.JSON")
    args = parser.parse_args()

    engine = Engine()

    # Register minimal builtin plugins. Real loader would be dynamic.
    engine.register_plugin(NmapPlugin())

    # Classify target and display detected kind
    from core.models import Target

    if args.doctor and not args.target:
        # run doctor without a target
        target = None
        print("Running doctor without target...")
    else:
        if args.target:
            target = Target.from_string(args.target)
            print(f"Detected target: {target.host} (type={target.kind})")
        else:
            target = None

    # Print detected tool availability summary
    print("\nDetected tool availability summary:")
    for tool, info in sorted(engine.available_binaries.items()):
        if isinstance(info, dict):
            binp = info.get("binary")
            pyp = info.get("python")
            status = "INSTALLED" if binp else ("PYTHON_ONLY" if pyp else "MISSING")
            details = binp or ("python-module" if pyp else "-")
            print(f"- {tool}: {status} ({details})")
        else:
            status = "INSTALLED" if info else "MISSING"
            print(f"- {tool}: {status}")

    # If user asked for a health check, offer to install missing tools, then write report
    if args.doctor:
        import json, sys, platform, os
        info = {
            "os": platform.platform(),
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
        }

        # Use a fresh detection for doctor so saved inventories do not influence
        # the generated report. This ensures `installed_tools.txt` is replaced
        # with a newly generated mapping.
        fresh_tools = engine.detect_binaries()
        info["tools"] = fresh_tools

        # During --doctor we may offer to install missing tools after confirmation.
        # This is interactive by default; use `--yes` to auto-accept.
        missing = [t for t, v in fresh_tools.items() if not (isinstance(v, dict) and v.get("binary") or (not isinstance(v, dict) and v)) and not (isinstance(v, dict) and v.get("python"))]
        if missing:
            print("\nThe following tools appear missing:")
            for t in missing:
                print(f"- {t}")
            do_install = False
            if args.yes:
                do_install = True
            else:
                try:
                    ans = input("Attempt to install missing tools now? [y/N]: ").strip().lower()
                    do_install = (ans == "y")
                except Exception:
                    do_install = False

            if do_install:
                for t in missing:
                    try:
                        ok = engine.ensure_tool(t, attempt_install=True)
                        print(f"Install attempt for {t}: {ok}")
                    except Exception as exc:
                        print(f"Failed to install {t}: {exc}")

                # refresh the info mapping after attempts using a fresh detect
                refreshed = engine.detect_binaries()
                info["tools"] = refreshed

        # Persist doctor output next to this script but avoid printing the entire JSON
        try:
            base = os.path.dirname(__file__)
            out_path = os.path.join(base, "installed_tools.txt")
            tmp_path = out_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)
                f.flush()
                try:
                    import os
                    os.fsync(f.fileno())
                except Exception:
                    pass
            # atomic replace
            import os
            os.replace(tmp_path, out_path)
            print(f"Doctor report saved to {out_path} (not printed to console)")
        except Exception as exc:
            print("Failed to write installed_tools.txt:", exc)
        sys.exit(0)

    results = engine.run_target(target, plugin_names=args.plugins)

    # If user passed an IP to scan via rustscan, run rustscan and save Discovery.JSON
    msf_patch_targets = []
    if args.ip:
        import subprocess, os

        # ensure rustscan is available
        rust_info = engine.available_binaries.get("rustscan")
        rust_path = None
        if isinstance(rust_info, dict):
            rust_path = rust_info.get("binary")
        else:
            rust_path = rust_info

        if not rust_path:
            print("rustscan is not installed or not found on PATH. Aborting rustscan run.")
        else:
            from core.statistics import ScanHistoryManager

            history = ScanHistoryManager()
            discovery_path = os.path.abspath("discovery.json")
            try:
                os.remove(discovery_path)
            except FileNotFoundError:
                pass
            profile, decision, args_list = build_adaptive_rustscan_command(
                args.ip,
                history=history,
                rust_bin=rust_path,
                output_path=discovery_path,
            )
            config = decision.config
            print(
                f"Network profile: {profile.quality} "
                f"(latency={profile.average_latency_ms}, loss={profile.packet_loss_percent}%)"
            )
            print(f"Adaptive RustScan strategy: {decision.reason}")
            # Let rustscan write the output file itself (discovery.json). Stream stdout
            # for live port detection but do not write the output here.
            print(f"Running: {' '.join(args_list)}")
            try:
                scan_started = time.monotonic()
                proc = subprocess.Popen(args_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                re_port_tcp = re.compile(r"(\d+)\s*/\s*tcp[^\n]*open", re.IGNORECASE)
                re_json_port = re.compile(r'"port"\s*:\s*(\d+)')
                seen = set()
                output_queue = queue.Queue()

                def collect_output():
                    try:
                        for output_line in proc.stdout:
                            output_queue.put(output_line)
                    finally:
                        output_queue.put(None)

                output_thread = threading.Thread(target=collect_output, daemon=True)
                output_thread.start()
                last_output_at = time.monotonic()
                stalled = False
                with ProgressSpinner("RustScan is running"):
                    while True:
                        try:
                            line = output_queue.get(timeout=0.5)
                        except queue.Empty:
                            if proc.poll() is not None:
                                break
                            if time.monotonic() - last_output_at >= RUSTSCAN_STALL_TIMEOUT_SECONDS:
                                stalled = True
                                print(
                                    f"\nRustScan produced no output for {RUSTSCAN_STALL_TIMEOUT_SECONDS} seconds; stopping it.",
                                    flush=True,
                                )
                                proc.terminate()
                                break
                            continue

                        if line is None:
                            break
                        last_output_at = time.monotonic()
                        # check for open port patterns
                        m = re_port_tcp.search(line)
                        if m:
                            port = m.group(1)
                            if port not in seen:
                                seen.add(port)
                                print(f"Open port found: {port}/tcp", flush=True)
                            continue
                        mj = re_json_port.search(line)
                        if mj:
                            port = mj.group(1)
                            if port not in seen:
                                seen.add(port)
                                print(f"Open port found (json): {port}/tcp", flush=True)

                if stalled:
                    try:
                        rc = proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        print("RustScan did not stop after termination; killing it.", flush=True)
                        proc.kill()
                        rc = proc.wait()
                    print(f"rustscan stopped after a {RUSTSCAN_STALL_TIMEOUT_SECONDS}-second stall")
                else:
                    rc = proc.wait()
                if not stalled and rc != 0:
                    print(f"rustscan exited with code {rc}")
                elif not stalled:
                    if not os.path.exists(discovery_path):
                        write_empty_discovery_report(discovery_path, args.ip)
                        print(f"No open ports found; wrote empty discovery report to {discovery_path}")
                    print("rustscan completed")
                history.record_scan(
                    target=args.ip,
                    latency=profile.average_latency_ms,
                    packet_loss=profile.packet_loss_percent,
                    batch_size=config.batch_size,
                    timeout=config.timeout_ms,
                    scan_duration=time.monotonic() - scan_started,
                    open_ports_found=len(seen),
                    network_quality=profile.quality,
                    network_type=profile.network_type,
                )
                history.close()
                # After rustscan completes, if msfconsole is available, parse this run's report
                # and perform searches for found services/versions.
                msf_path = shutil.which("msfconsole") or "/usr/bin/msfconsole"
                if msf_path and rc == 0:
                    if os.path.exists(discovery_path):
                        try:
                            services = parse_discovery_services(discovery_path)
                        except (OSError, ValueError) as exc:
                            print(f"Failed to parse {discovery_path}: {exc}")
                            services = []

                        # dedupe
                        uniq = []
                        seen_sv = set()
                        for s, v in services:
                            if not has_version_number(v):
                                continue
                            key = f"{s}||{v}"
                            if key in seen_sv:
                                continue
                            seen_sv.add(key)
                            uniq.append((s, v))

                        # run msf searches
                        import shlex
                        # prepare msf output file next to main.py
                        msf_out = os.path.join(os.path.dirname(__file__), "msffindings.txt")
                        for svc, ver in uniq:
                            # Product/version names are what Metasploit indexes;
                            # skip services without attached product/version data.
                            term = ver.strip()
                            cmd = [msf_path, "-q", "-x", f"search {term}; exit"]
                            try:
                                with ProgressSpinner(f"Searching Metasploit for {term}"):
                                    completed = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                                output = completed.stdout or ""
                                if has_msf_module_results(output):
                                    print(f"\n=== Metasploit results: {term} ===")
                                    print(output, end="" if output.endswith("\n") else "\n")
                                if has_msf_exploit_results(output) and term not in msf_patch_targets:
                                    msf_patch_targets.append(term)
                                with open(msf_out, "a", encoding="utf-8") as mf:
                                    mf.write(f"=== Search: {term}\n")
                                    mf.write(output)
                                    mf.write("\n\n")
                            except Exception as e:
                                print(f"msfconsole search failed for {term}: {e}")
                    else:
                        print("RustScan did not produce discovery.json; skipping Metasploit searches")
                elif rc != 0:
                    print("Skipping Metasploit searches because RustScan failed")
                else:
                    print("msfconsole executable not found; skipping Metasploit searches")
            except FileNotFoundError:
                print("rustscan executable not found when attempting to run.")
            except Exception as e:
                print("rustscan run failed:", e)

    print("\nRecommendations:")
    for rec in results.recommendations:
        print(f"- {rec.tool} (score={rec.confidence:.2f}) — {rec.reason}")
    for term in msf_patch_targets:
        print(f"- Patch {term}")


if __name__ == "__main__":
    main()
