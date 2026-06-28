#!/usr/bin/env bash
# Deploy LAN Network Scanner to a Raspberry Pi over SSH.
#
# Usage:
#   ./scripts/deploy-pi.sh [ssh-host]
#   ./scripts/deploy-pi.sh pi-scanner
#   INSTALL_STARLINK=1 ./scripts/deploy-pi.sh pi-scanner
#
# Default host: pi-scanner (192.168.1.183 in ~/.ssh/config)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-pi-scanner}"
REMOTE_DIR="${REMOTE_DIR:-Projects/lan-network-scanner}"

echo "== Deploying to $HOST =="
echo "Local:  $ROOT"
echo "Remote: ~/$REMOTE_DIR"
echo

REMOTE_PATH="$(ssh "$HOST" "mkdir -p ~/$REMOTE_DIR && cd ~/$REMOTE_DIR && pwd")"

rsync -avz --delete \
  --exclude '.venv/' \
  --exclude '.bin/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '.git/' \
  --exclude '.cursor/' \
  "$ROOT/" "$HOST:$REMOTE_PATH/"

echo
echo "Running remote setup..."
ssh "$HOST" "INSTALL_STARLINK=${INSTALL_STARLINK:-0} bash '$REMOTE_PATH/scripts/pi-remote-setup.sh'"

PI_IP="$(ssh "$HOST" "hostname -I | awk '{print \$1}'")"
echo
echo "== Deploy complete =="
echo "Open: http://${PI_IP}:8080"
echo "SSH:  ssh $HOST"
echo "Logs: ssh $HOST 'journalctl --user -u lan-network-scanner -f'"
