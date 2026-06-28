#!/usr/bin/env bash
# Install grpcurl into the project .bin/ folder (no sudo required).
# Prints the path to grpcurl on success.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/.bin"
TARGET="$BIN_DIR/grpcurl"
GRPCURL_VERSION="1.9.3"
PYTHON="${ROOT}/.venv/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3 || true)"
fi

if [[ -x "$TARGET" ]]; then
  echo "$TARGET"
  exit 0
fi

if command -v grpcurl >/dev/null 2>&1; then
  echo "$(command -v grpcurl)"
  exit 0
fi

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "arm64" ;;
    i386|i686) echo "x86_32" ;;
    armv7l) echo "armv7" ;;
    armv6l) echo "armv6" ;;
    *)
      echo "unsupported architecture: $(uname -m)" >&2
      return 1
      ;;
  esac
}

download_file() {
  local url="$1"
  local dest="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
    return $?
  fi

  if command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
    return $?
  fi

  if [[ -n "$PYTHON" && -x "$PYTHON" ]]; then
    "$PYTHON" - "$url" "$dest" <<'PY'
import sys
import urllib.request
from pathlib import Path

url, dest = sys.argv[1], sys.argv[2]
request = urllib.request.Request(url, headers={"User-Agent": "lan-network-scanner/1.0"})
with urllib.request.urlopen(request, timeout=120) as response:
    Path(dest).write_bytes(response.read())
PY
    return $?
  fi

  echo "Need curl, wget, or python3 to download grpcurl." >&2
  return 1
}

extract_archive() {
  local archive="$1"
  local dest_dir="$2"

  if tar -xzf "$archive" -C "$dest_dir" 2>/dev/null; then
    return 0
  fi

  if [[ -n "$PYTHON" && -x "$PYTHON" ]]; then
    "$PYTHON" - "$archive" "$dest_dir" <<'PY'
import sys
import tarfile
from pathlib import Path

archive, dest_dir = sys.argv[1], sys.argv[2]
with tarfile.open(archive, "r:gz") as tar:
    tar.extractall(dest_dir)
print(dest_dir)
PY
    return $?
  fi

  echo "Need tar or python3 to extract grpcurl archive." >&2
  return 1
}

ARCH="$(detect_arch)"
ARCHIVE="grpcurl_${GRPCURL_VERSION}_linux_${ARCH}.tar.gz"
URL="https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/${ARCHIVE}"
TMP="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "Downloading grpcurl v${GRPCURL_VERSION} for linux_${ARCH}..." >&2
if ! download_file "$URL" "$TMP/$ARCHIVE"; then
  echo "Download failed: $URL" >&2
  exit 1
fi

mkdir -p "$BIN_DIR"
if ! extract_archive "$TMP/$ARCHIVE" "$TMP"; then
  exit 1
fi

if [[ ! -f "$TMP/grpcurl" ]]; then
  echo "Archive did not contain grpcurl binary." >&2
  exit 1
fi

install -m 0755 "$TMP/grpcurl" "$TARGET"

if ! "$TARGET" -version >/dev/null 2>&1; then
  echo "Installed binary does not run: $TARGET" >&2
  exit 1
fi

echo "Installed grpcurl to $TARGET" >&2
echo "$TARGET"
