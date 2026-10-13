#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 -m venv .venv
.venv/bin/python -m pip install --cache-dir "$PWD/.cloudguard/cache/pip" -r backend/requirements.lock
(cd frontend && npm ci --cache "$PWD/../.cloudguard/cache/npm" && npm run build)
.venv/bin/python -m unittest discover -s backend/tests -v
