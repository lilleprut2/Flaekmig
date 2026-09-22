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

