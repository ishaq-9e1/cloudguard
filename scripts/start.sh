#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
if [[ ! -x .venv/bin/python || ! -d frontend/node_modules ]]; then
  echo 'Run bash scripts/setup.sh first.' >&2
  exit 1
fi
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 &
api_pid=$!
(cd frontend && exec npm run dev -- --host 127.0.0.1 --port 5173 --strictPort) &
ui_pid=$!
cleanup() { kill "$api_pid" "$ui_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
wait -n "$api_pid" "$ui_pid"
