# Flaekmig — Minimal cybersecurity orchestration platform (MVP)

This repository contains a minimal, extensible Python-only skeleton for Flaekmig — a cross-platform orchestration/decision engine designed to coordinate existing security tooling.

Key principles:
- Python standard library first
- Modular plugin-based design
- Decision engine driven by rules
- CLI-first, UI later

IP scan workflow
----------------

Run an adaptive RustScan scan with:

```bash
python3 main.py -ip 192.168.74.129
```

The `-ip` flow profiles the target with bounded ping probes before starting
RustScan. The measured connection quality selects the initial batch size and
timeout:

| Quality | Batch size | Timeout |
| --- | ---: | ---: |
| `EXCELLENT` | 1000 | 1500 ms |
| `GOOD` | 500 | 2000 ms |
| `FAIR` | 100 | 3000 ms |
| `POOR` | 25 | 6000 ms |
| `UNREACHABLE` | 5 | 10000 ms |

For the default full TCP-port scan, RustScan uses `--range 1-65535` (RustScan
2.x syntax), followed by Nmap service detection with `-sV`. The report is
The normalized report is written to `discovery.json` in the current working
directory, while the raw Nmap output is preserved in `nmapdump.json`. A
successful scan with no open ports still receives a target-specific empty report, while a
failed scan does not reuse an older report.

The CLI displays progress while RustScan and Metasploit run. RustScan is
stopped after 300 seconds without output, preventing an indefinitely running
spinner while allowing slow full-port scans to complete. Version-bearing
services from the current discovery report are searched with `msfconsole`; the
console shows actual module matches, and patch recommendations are emitted only
for exploit modules.

Use delicate mode when the target or network requires a less aggressive scan:

```bash
python3 main.py -ip 192.168.74.129 -d
```

The `-d` / `--delicate` option forces the RustScan batch size to `50` while
keeping the adaptive timeout selected from the network profile.

See `core/` for engine and rule logic and `plugins/` for plugin implementations.

Getting started (local development)
----------------------------------

On macOS / Linux:

```bash
./scripts/setup_env.sh
source .venv/bin/activate
python3 -m unittest discover -v
```

On Windows (PowerShell):

```powershell
.\\scripts\\setup_env.ps1
.\.venv\Scripts\Activate.ps1
python -m unittest discover -v
```

Push to GitHub and CI will run the unit tests automatically.

Usage
-----

### Basic target scan

Scan a single host or target using the default engine flow:

```bash
python3 main.py 127.0.0.1
```

This registers the available plugins, runs the selected scan, and prints any
recommendations generated from the findings.

### Adaptive IP scan

Run the RustScan-based IP profiling workflow:

```bash
python3 main.py -ip 192.168.74.129
```

This performs a quick network-quality profile, chooses a RustScan batch size and
timeout based on latency and packet loss, then runs a full TCP scan and service
detection. Results are written to `discovery.json` and any matching Metasploit
modules are written to `msffindings.txt`.

### Doctor / tool inventory

Check which required tools are present on the system:

```bash
python3 main.py --doctor
```

This writes an inventory file named `installed_tools.txt` next to the project.
Missing tools are listed and you are asked whether they should be installed.
Use `--yes` to accept all installation prompts automatically:

```bash
python3 main.py --doctor --yes
```

On Arch-based Linux systems, the doctor/install flow checks whether the
BlackArch repository is configured before using pacman. If it is missing, the
official BlackArch strap script is downloaded and run, then pacman refreshes
its package database so security tools can be installed. This may require
`sudo` privileges. On systems without `curl`, the fallback adds the BlackArch
repository entries directly to `/etc/pacman.conf`.

### Run tests

```bash
python3 -m unittest discover -v
```

### Environment setup

On Linux/macOS:

```bash
./scripts/setup_env.sh
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.\scripts\setup_env.ps1
.\.venv\Scripts\Activate.ps1
```

Adaptive RustScan engine
------------------------

The adaptive implementation is split into small standard-library components:

- `core/network_profiler.py` sends five bounded ping probes and classifies latency, packet loss, responsiveness, and likely network type (`LOCAL_LAN`, `VPN`, `INTERNET_HOST`, or `HIGH_LATENCY_NETWORK`).
- `core/rustscan_optimizer.py` selects a quality-based baseline and learns from high-scoring history after ten scans.
- `core/statistics.py` owns the SQLite history database and score calculation.
- `core/decision_engine.py` coordinates profiling and optimization.
- `plugins/rustscan/plugin.py` profiles before every scan, builds the RustScan command, parses open ports, and records the execution.
- `main.py` integrates the same profiling and optimization decision into the
	`-ip` CLI path and records scan history in SQLite.

Example integration:

```python
from core.statistics import ScanHistoryManager
from plugins.rustscan.plugin import RustScanPlugin
from core.models import Target

history = ScanHistoryManager("data/scan_history.db")
plugin = RustScanPlugin(history=history)
result = plugin.run(Target.from_string("192.0.2.10"))
print(result.config, result.ports)
plugin.close()
```

The history schema is created automatically:

```sql
CREATE TABLE scan_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	latency REAL,
	packet_loss REAL NOT NULL,
	batch_size INTEGER NOT NULL,
	timeout INTEGER NOT NULL,
	scan_duration REAL NOT NULL,
	open_ports_found INTEGER NOT NULL,
	network_quality TEXT NOT NULL,
	score REAL NOT NULL,
	network_type TEXT NOT NULL
);
```

The score is `(open_ports_found * 10) - scan_duration - (packet_loss * 5)`. The
optimizer uses the quality baseline until ten records exist for the target,
then reduces batch size after loss and cautiously increases it when history is
consistently high-scoring.

Generated files
---------------

- `discovery.json` — JSON service report from the current `-ip` scan.
- `nmapdump.json` — Raw Nmap output captured before `discovery.json` is normalized.
- `msffindings.txt` — Metasploit search output for version-bearing services.
- `installed_tools.txt` — tool inventory generated by `--doctor`.

