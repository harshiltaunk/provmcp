#!/usr/bin/env bash
# Set up ProvMCP on macOS (13+). Idempotent — safe to re-run.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Checking Homebrew"
if ! command -v brew >/dev/null 2>&1; then
  echo "    Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

echo "==> Checking Python 3.11"
if ! command -v python3.11 >/dev/null 2>&1; then
  brew install python@3.11
fi

echo "==> Creating virtualenv at .venv"
if [ ! -d .venv ]; then
  python3.11 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Installing dependencies"
pip install -q -U pip
pip install -q -e ".[dev]"

echo "==> Running the test suite"
pytest -q

echo
echo "All set. Activate the environment with:"
echo "    source .venv/bin/activate"
echo "Then run:"
echo "    provmcp version"
echo "    provmcp doctor"
