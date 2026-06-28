#!/usr/bin/env bash
# Desktop launcher: restart the scanner and open the browser.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python3"
URL="http://localhost:8080"
LOG="/tmp/lan-network-scanner.log"
LAUNCH_LOG="/tmp/lan-network-scanner-launch.log"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >>"$LAUNCH_LOG"
}

notify_error() {
  local message="$1"
  log "ERROR: $message"
  if command -v zenity >/dev/null 2>&1; then
    zenity --error --title="Network Scanner" --text="$message" 2>/dev/null || true
  elif command -v notify-send >/dev/null 2>&1; then
    notify-send "Network Scanner" "$message" 2>/dev/null || true
  fi
}

server_up() {
  "$PYTHON" -c "
import urllib.request
urllib.request.urlopen('$URL/', timeout=2)
" 2>/dev/null
}

open_browser() {
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
    return 0
  fi
  if command -v gio >/dev/null 2>&1; then
    gio open "$URL" >/dev/null 2>&1 &
    return 0
  fi
  if command -v gnome-open >/dev/null 2>&1; then
    gnome-open "$URL" >/dev/null 2>&1 &
    return 0
  fi
  "$PYTHON" -c "import webbrowser; webbrowser.open('$URL')" 2>/dev/null &
  return 0
}

log "Launch started (pid $$)"

if [[ ! -x "$PYTHON" ]]; then
  notify_error "Python virtualenv not found.

Run in a terminal:
cd $ROOT
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt"
  exit 1
fi

log "Restarting scanner (picks up Starlink/grpcurl changes)..."
pkill -f "$ROOT/run.py" 2>/dev/null || true
sleep 0.5

log "Starting server..."
nohup "$PYTHON" "$ROOT/run.py" >>"$LOG" 2>&1 &
started=0
for _ in $(seq 1 40); do
  if server_up; then
    started=1
    break
  fi
  sleep 0.25
done

if [[ "$started" -ne 1 ]]; then
  notify_error "Scanner did not start. Check log:
$LOG"
  exit 1
fi

log "Server running on $URL"
open_browser
log "Browser open requested for $URL"
exit 0
