#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv"

if [[ ! -d "$VENV" ]]; then
  echo "Error: $VENV not found." >&2
  exit 1
fi

mapfile -t PYTHON_BINARIES < <(find "$VENV/bin" -maxdepth 1 -type f -name 'python*' | sort)

for binary in "${PYTHON_BINARIES[@]}"; do
  if file "$binary" | grep -q "ELF .* executable"; then
    echo "Removing capabilities from $binary"
    sudo setcap -r "$binary" 2>/dev/null || true
  fi
done

echo "Done."
