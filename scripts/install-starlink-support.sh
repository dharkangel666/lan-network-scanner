#!/usr/bin/env bash
# One-time optional setup: install grpcurl + cache Starlink protoset for client list API.
# The router (port 9000) usually does NOT expose grpcurl reflection; export schema from
# the dish at 192.168.100.1:9200 first, then query wifiGetClients on the router.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$HOME/.cache/lan-network-scanner"
DISH_PROTOSET="$CACHE/dish.protoset"
ROUTER_PROTOSET="$CACHE/router.protoset"
LOG="$CACHE/starlink-setup.log"
DISH="192.168.100.1:9200"

chmod +x "$ROOT/scripts/install-grpcurl.sh" \
         "$ROOT/scripts/install-starlink-support.sh" \
         "$ROOT/scripts/launch.sh" 2>/dev/null || true

mkdir -p "$CACHE"
: >"$LOG"

log() {
  echo "$*"
  echo "$*" >>"$LOG"
}

run() {
  log "+ $*"
  "$@" >>"$LOG" 2>&1
  return $?
}

section() {
  echo
  log "== $* =="
}

section "Network Scanner — Starlink setup"

GRPCURL=""
if command -v grpcurl >/dev/null 2>&1; then
  GRPCURL="$(command -v grpcurl)"
  log "grpcurl: $GRPCURL"
else
  log "Downloading grpcurl binary (no sudo)..."
  if GRPCURL="$(/bin/bash "$ROOT/scripts/install-grpcurl.sh" 2>>"$LOG")"; then
    log "grpcurl ready: $GRPCURL"
  else
    log "Could not install grpcurl automatically."
    log "Run manually: bash $ROOT/scripts/install-grpcurl.sh"
    tail -15 "$LOG" || true
    read -r -p "Press Enter to close..."
    exit 1
  fi
fi

grpcurl() {
  "$GRPCURL" "$@"
}

GW="$(ip route | awk '/default/ {print $3; exit}')"
ROUTER="${GW:-192.168.1.1}:9000"

section "Your network"
log "Default gateway (Starlink router?): ${GW:-unknown}"
log "Router gRPC target: $ROUTER"
log "Dish gRPC target: $DISH"

section "Reachability"
if ping -c 1 -W 2 "${GW:-192.168.1.1}" >/dev/null 2>&1; then
  log "Ping router OK"
else
  log "WARNING: cannot ping router at ${GW:-192.168.1.1}"
fi
if ping -c 1 -W 2 192.168.100.1 >/dev/null 2>&1; then
  log "Ping dish (192.168.100.1) OK"
else
  log "WARNING: cannot ping dish at 192.168.100.1 (protoset export may fail)"
fi

section "Step 1 — export protocol schema from dish"
rm -f "$DISH_PROTOSET" "$ROUTER_PROTOSET"
if run grpcurl -plaintext -max-time 10 -protoset-out "$DISH_PROTOSET" "$DISH" describe SpaceX.API.Device.Device; then
  log "Saved dish protoset: $DISH_PROTOSET ($(wc -c <"$DISH_PROTOSET") bytes)"
else
  log "Dish protoset export failed. Trying router $ROUTER ..."
  if run grpcurl -plaintext -max-time 10 -protoset-out "$ROUTER_PROTOSET" "$ROUTER" describe SpaceX.API.Device.Device; then
    log "Saved router protoset: $ROUTER_PROTOSET ($(wc -c <"$ROUTER_PROTOSET") bytes)"
    cp "$ROUTER_PROTOSET" "$DISH_PROTOSET"
  else
    log "FAILED to export protoset from dish or router."
    log "grpcurl needs the Starlink protobuf schema. Without it you only get guess mode."
    log "Full log: $LOG"
    tail -20 "$LOG" || true
    read -r -p "Press Enter to close..."
    exit 1
  fi
fi

PROTOSET="$DISH_PROTOSET"
section "Step 2 — query connected clients on router"
PAYLOADS=('{"wifiGetClients":{}}' '{"wifi_get_clients":{}}')
SUCCESS=0
for payload in "${PAYLOADS[@]}"; do
  log "Trying $ROUTER with payload $payload"
  if OUT="$(grpcurl -plaintext -max-time 10 -protoset "$PROTOSET" -d "$payload" "$ROUTER" SpaceX.API.Device.Device/Handle 2>&1)"; then
    echo "$OUT"
    echo "$OUT" >>"$LOG"
    if echo "$OUT" | grep -qE 'macAddress|mac_address|"clients"'; then
      log "SUCCESS — Starlink client list returned."
      SUCCESS=1
      break
    fi
    log "Call succeeded but response had no clients (empty list or unexpected format)."
  else
    log "Call failed:"
    echo "$OUT"
    echo "$OUT" >>"$LOG"
  fi
done

echo
if [[ "$SUCCESS" -eq 1 ]]; then
  log "Starlink setup complete."
  log "Restart Network Scanner, then click Scan Network."
else
  log "Starlink client API still not working."
  log "Common causes:"
  log "  • Router in bypass mode (Starlink not managing Wi-Fi)"
  log "  • Third-party router (no Starlink API on your gateway)"
  log "  • Router firmware too old for wifiGetClients"
  log "Full log saved to: $LOG"
  tail -30 "$LOG" || true
fi

echo
read -r -p "Press Enter to close..."
