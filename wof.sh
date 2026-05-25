#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" == "Linux" ]]; then
  if [[ ! -f .venv/bin/activate ]]; then
    echo "[!] Creating virtual environment (.venv)..."
    python3 -m venv .venv
  fi
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

python3 WallofFlippers.py "$@"
