#!/usr/bin/env bash
# Post-sync setup on the Raspberry Pi (venv, systemd user service).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PYTHON="$ROOT/.venv/bin/python3"
SERVICE_NAME="lan-network-scanner.service"
SERVICE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

echo "== LAN Network Scanner — Pi setup =="
echo "Project: $ROOT"

if [[ ! -d "$ROOT/.venv" ]]; then
  echo "Creating virtualenv..."
  python3 -m venv --copies "$ROOT/.venv"
else
  echo "Using existing virtualenv."
fi

"$PYTHON" -m pip install --upgrade pip -q
"$PYTHON" -m pip install -r "$ROOT/requirements.txt" -q
echo "Python dependencies installed."

chmod +x "$ROOT/scripts/"*.sh 2>/dev/null || true

echo "Installing grpcurl for this architecture..."
bash "$ROOT/scripts/install-grpcurl.sh" >/dev/null || echo "grpcurl install skipped (Starlink features optional)."

mkdir -p "$SERVICE_DIR"
cat >"$SERVICE_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=LAN Network Scanner
After=network-online.target avahi-daemon.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
ExecStart=$PYTHON $ROOT/run.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable "$SERVICE_NAME"
systemctl --user restart "$SERVICE_NAME"

echo
echo "Waiting for server..."
ready=0
for _ in $(seq 1 30); do
  if "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=2)" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.5
done

if [[ "$ready" -eq 1 ]]; then
  echo "Scanner is running."
else
  echo "Warning: service started but HTTP check failed. Logs:"
  journalctl --user -u "$SERVICE_NAME" -n 20 --no-pager || true
  exit 1
fi

echo
systemctl --user --no-pager status "$SERVICE_NAME" || true

echo
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo
if ! getcap "$PYTHON" 2>/dev/null | grep -q cap_net_raw; then
  echo "Optional — active ARP scans (run once on the Pi):"
  echo "  cd $ROOT"
  echo "  sudo ./scripts/setup-capabilities.sh"
  echo "  systemctl --user restart $SERVICE_NAME"
fi

if [[ "${INSTALL_STARLINK:-0}" == "1" ]]; then
  echo
  echo "Installing Starlink support..."
  bash "$ROOT/scripts/install-starlink-support.sh" || echo "Starlink setup failed — run manually later."
fi
