#!/usr/bin/env bash
# scripts/record-demo.sh — record an asciinema cast of `make demo`.
#
# Usage: scripts/record-demo.sh [output.cast]
# Default output path: docs/assets/demo.cast
#
# Requires asciinema (brew install asciinema / pipx install asciinema).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-${ROOT}/docs/assets/demo.cast}"

if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema is not installed. brew install asciinema" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
echo "[record-demo] writing cast to $OUT"

asciinema rec \
  --overwrite \
  --idle-time-limit 1 \
  --title "Omega PoC v0.0.1 — make demo" \
  --command "make -C $ROOT demo" \
  "$OUT"

echo "[record-demo] cast saved. Upload to asciinema.org or embed via SVG:"
echo "  asciinema upload $OUT"
