# Flaekmig — Minimal cybersecurity orchestration platform (MVP)

This repository contains a minimal, extensible Python-only skeleton for Flaekmig — a cross-platform orchestration/decision engine designed to coordinate existing security tooling.

Key principles:
- Python standard library first
- Modular plugin-based design
- Decision engine driven by rules
- CLI-first, UI later

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

Adaptive RustScan engine
------------------------

The adaptive implementation is split into small standard-library components:

- `core/network_profiler.py` sends five bounded ping probes and classifies latency, packet loss, responsiveness, and likely network type (`LOCAL_LAN`, `VPN`, `INTERNET_HOST`, or `HIGH_LATENCY_NETWORK`).
- `core/rustscan_optimizer.py` selects a quality-based baseline and learns from high-scoring history after ten scans.
- `core/statistics.py` owns the SQLite history database and score calculation.
- `core/decision_engine.py` coordinates profiling and optimization.
- `plugins/rustscan/plugin.py` profiles before every scan, builds the RustScan command, parses open ports, and records the execution.

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
optimizer uses the requested baselines until ten records exist for the target,
then reduces batch size after loss and cautiously increases it when history is
consistently high-scoring.

