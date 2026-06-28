#!/usr/bin/env bash
# Send a desktop notification for Network Scanner (requires notify-send / libnotify-bin).
set -euo pipefail

TITLE="${1:-Network Scanner}"
BODY="${2:-}"

if [[ -z "$BODY" ]]; then
  echo "Usage: $0 \"Title\" \"Message body\"" >&2
  exit 1
fi

if ! command -v notify-send >/dev/null 2>&1; then
  echo "notify-send not found. Install libnotify-bin." >&2
  exit 1
fi

exec notify-send -a "Network Scanner" "$TITLE" "$BODY"
