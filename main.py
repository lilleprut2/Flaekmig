#!/usr/bin/env python3
"""Flaekmig CLI entrypoint (minimal)."""
import argparse
from core.engine import Engine
from plugins.nmap.plugin import NmapPlugin


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
    if args.ip:
        import shutil, subprocess, json, os

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
            # Let rustscan write the output file itself (discovery.json). Stream stdout
            # for live port detection but do not write the output here.
            exe = shutil.which('rustscan') or rust_path
            # Command exactly as requested: rustscan -a IP --ulimit 5000 --top  -- -sV -oN discovery.json
            args_list = [exe, "-a", args.ip, "--ulimit", "5000", "--top", "--", "-sV", "-oN", "discovery.json"]
            print(f"Running: {' '.join(args_list)}")
            import re
            try:
                proc = subprocess.Popen(args_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                re_port_tcp = re.compile(r"(\d+)\s*/\s*tcp[^\n]*open", re.IGNORECASE)
                re_json_port = re.compile(r'"port"\s*:\s*(\d+)')
                seen = set()
                for line in proc.stdout:
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

                rc = proc.wait()
                if rc != 0:
                    print(f"rustscan exited with code {rc}")
                else:
                    print("rustscan completed")
                # rustscan writes discovery.json itself; do not manage file here.
                # After rustscan completes, if msfconsole is available, parse discovery.json
                # and perform searches for found services/versions.
                msf_path = shutil.which("msfconsole")
                if msf_path:
                    # discovery.json is created in cwd by rustscan using -oN discovery.json
                    disc_path = os.path.join(os.getcwd(), "discovery.json")
                    if os.path.exists(disc_path):
                        services = []
                        # try JSON first
                        try:
                            with open(disc_path, "r", encoding="utf-8") as df:
                                import json as _json
                                data = _json.load(df)
                            # Expecting rustscan/nmap JSON structure: look for hosts -> ports
                            for host in (data.get("hosts") or []):
                                for port in host.get("ports", []):
                                    svc = port.get("service") or {}
                                    name = svc.get("name") or port.get("service_name")
                                    ver = svc.get("product") or svc.get("version") or ""
                                    if name:
                                        services.append((name, ver))
                        except Exception:
                            # fallback: parse as nmap -oN human output
                            try:
                                with open(disc_path, "r", encoding="utf-8") as df:
                                    txt = df.read()
                                # lines like: 22/tcp open ssh OpenSSH 7.6p1 Ubuntu
                                for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?", txt):
                                    svc = m.group(2)
                                    ver = (m.group(3) or "").strip()
                                    services.append((svc, ver))
                            except Exception:
                                services = []

                        # dedupe
                        uniq = []
                        seen_sv = set()
                        for s, v in services:
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
                            term = svc
                            if ver:
                                term = f"{svc} {ver}"
                            cmd = [msf_path, "-q", "-x", f"search {term}; exit"]
                            print(f"Running msfconsole search for: {term}")
                            try:
                                completed = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                                with open(msf_out, "a", encoding="utf-8") as mf:
                                    mf.write(f"=== Search: {term}\n")
                                    mf.write(completed.stdout or "")
                                    mf.write("\n\n")
                            except Exception as e:
                                print("msfconsole search failed:", e)
                    else:
                        print("discovery.json not found in cwd; skipping msfconsole searches")
                else:
                    print("msfconsole not found on PATH; skipping Metasploit searches")
            except FileNotFoundError:
                print("rustscan executable not found when attempting to run.")
            except Exception as e:
                print("rustscan run failed:", e)

    print("\nRecommendations:")
    for rec in results.recommendations:
        print(f"- {rec.tool} (score={rec.confidence:.2f}) — {rec.reason}")


if __name__ == "__main__":
    main()
