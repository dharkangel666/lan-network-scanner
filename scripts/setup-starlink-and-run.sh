#!/usr/bin/env bash
# Install grpcurl (Starlink connection data) and start the network scanner.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python3"
URL="http://localhost:8080"
LOG="/tmp/lan-network-scanner.log"

if [[ ! -x "$PYTHON" ]]; then
  echo "Virtualenv missing. Run: cd $ROOT && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

echo "==> Checking grpcurl (Starlink Wi-Fi/Ethernet lookup)..."
if command -v grpcurl >/dev/null 2>&1; then
  echo "    grpcurl already installed: $(command -v grpcurl)"
else
  echo "    Installing grpcurl (sudo password may be required)..."
  sudo apt-get update -qq
  sudo apt-get install -y grpcurl
  echo "    grpcurl installed."
fi

echo "==> Stopping any existing scanner on port 8080..."
pkill -f "$ROOT/run.py" 2>/dev/null || true
sleep 0.5

echo "==> Starting network scanner..."
nohup "$PYTHON" "$ROOT/run.py" >>"$LOG" 2>&1 &
for _ in $(seq 1 30); do
  if "$PYTHON" -c "import urllib.request; urllib.request.urlopen('$URL/', timeout=1)" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

if ! "$PYTHON" -c "import urllib.request; urllib.request.urlopen('$URL/', timeout=2)" 2>/dev/null; then
  echo "Scanner failed to start. Log:"
  tail -30 "$LOG" || true
  exit 1
fi

echo "==> Scanner running at $URL"
echo "    Log: $LOG"

GW="$(ip route | awk '/default/ {print $3; exit}')"
if [[ -n "$GW" ]] && command -v grpcurl >/dev/null 2>&1; then
  echo "==> Testing Starlink router API at ${GW}:9000..."
  if grpcurl -plaintext -max-time 3 -d '{"wifiGetClients":{}}' "${GW}:9000" SpaceX.API.Device.Device/Handle 2>/dev/null | head -3; then
    echo "    Starlink client API reachable — connection column will use router data."
  else
    echo "    Starlink API not reachable (normal if not on Starlink LAN or router in bypass mode)."
    echo "    Vendor-based guesses will still be used."
  fi
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL" >/dev/null 2>&1 &
elif command -v gnome-open >/dev/null 2>&1; then
  gnome-open "$URL" >/dev/null 2>&1 &
else
  "$PYTHON" -c "import webbrowser; webbrowser.open('$URL')"
fi

echo "==> Done. Click Scan Network in the browser."
