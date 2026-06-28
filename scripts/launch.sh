#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python3"
URL="http://localhost:8080"
LOG="/tmp/network-scanner.log"

server_running() {
  "$PYTHON" -c "
import urllib.request
urllib.request.urlopen('$URL/', timeout=1)
" 2>/dev/null
}

if ! server_running; then
  nohup "$PYTHON" "$ROOT/run.py" >>"$LOG" 2>&1 &
  for _ in $(seq 1 30); do
    if server_running; then
      break
    fi
    sleep 0.2
  done
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$URL"
else
  "$PYTHON" -c "import webbrowser; webbrowser.open('$URL')"
fi
