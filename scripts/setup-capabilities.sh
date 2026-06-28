#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="$ROOT/.venv"
PYTHON="$VENV/bin/python3"
REQUIREMENTS="$ROOT/requirements.txt"
CAPS="cap_net_raw,cap_net_admin=eip"

if ! command -v setcap >/dev/null 2>&1; then
  echo "Error: setcap not found. Install libcap2-bin:" >&2
  echo "  sudo apt install libcap2-bin" >&2
  exit 1
fi

if [[ ! -d "$VENV" ]]; then
  echo "Creating virtualenv..."
  python3 -m venv --copies "$VENV"
fi

if [[ -L "$PYTHON" ]]; then
  echo "Virtualenv Python is a symlink to the system interpreter."
  echo "Recreating the virtualenv with copied binaries so capabilities stay isolated..."
  python3 -m venv --clear --copies "$VENV"
  "$PYTHON" -m pip install --upgrade pip
  "$PYTHON" -m pip install -r "$REQUIREMENTS"
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "Error: $PYTHON not found." >&2
  exit 1
fi

mapfile -t PYTHON_BINARIES < <(find "$VENV/bin" -maxdepth 1 -type f -name 'python*' | sort)

if [[ ${#PYTHON_BINARIES[@]} -eq 0 ]]; then
  echo "Error: no Python executables found in $VENV/bin." >&2
  exit 1
fi

echo "Granting raw socket capabilities to virtualenv Python binaries:"
for binary in "${PYTHON_BINARIES[@]}"; do
  if file "$binary" | grep -q "ELF .* executable"; then
    echo "  $binary"
    sudo setcap "$CAPS" "$binary"
  fi
done

echo
echo "Installed capabilities:"
for binary in "${PYTHON_BINARIES[@]}"; do
  if file "$binary" | grep -q "ELF .* executable"; then
    getcap "$binary"
  fi
done
echo
echo "Done. Start the scanner normally with:"
echo "  cd $ROOT"
echo "  source .venv/bin/activate"
echo "  python run.py"
echo
echo "You should not need sudo for future runs."
