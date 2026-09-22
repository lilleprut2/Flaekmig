#!/usr/bin/env bash
# Cross-platform virtualenv setup helper for contributors (macOS/Linux)
set -euo pipefail

PYENV_DIR=".venv"

if [ -d "$PYENV_DIR" ]; then
  echo "Virtualenv already exists at $PYENV_DIR"
else
  python3 -m venv "$PYENV_DIR"
  echo "Created virtualenv at $PYENV_DIR"
fi

echo "Using virtualenv at: $PYENV_DIR"
VENV_PY="$PYENV_DIR/bin/python"
if [ ! -x "$VENV_PY" ]; then
  echo "ERROR: venv python not found or not executable: $VENV_PY" >&2
  exit 1
fi

echo "Upgrading pip and installing requirements using venv's python..."
"$VENV_PY" -m pip install --upgrade pip setuptools wheel
if [ -f requirements.txt ]; then
  "$VENV_PY" -m pip install -r requirements.txt
fi

echo "Setup complete. To use the venv in your shell run: source $PYENV_DIR/bin/activate"
echo "Or run commands directly with the venv python: $VENV_PY <args>"
