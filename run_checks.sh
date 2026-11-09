#!/usr/bin/env bash
# Toing — one-command checks: ruff + compile + tests.
# Usage: ./run_checks.sh
# PYTHON=/path/to/python override kar sakte ho; default .venv/bin/python.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-.venv/bin/python}"
if [ ! -x "$PYTHON" ] && [ -x "../.venv/bin/python" ]; then
    PYTHON="../.venv/bin/python"
fi
if [ ! -x "$PYTHON" ]; then
    PYTHON="python3"
fi
echo "Python: $PYTHON"

echo "[1/3] ruff check"
"$PYTHON" -m ruff check .

echo "[2/3] compile"
"$PYTHON" -m compileall -q .

echo "[3/3] tests (mocked transport, koi live call nahi)"
"$PYTHON" -m unittest discover -s tests -p 'test_*.py' -v

echo "ALL CHECKS GREEN"
