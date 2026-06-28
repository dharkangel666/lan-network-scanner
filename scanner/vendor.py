import re
import threading
import urllib.request
from pathlib import Path

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
CACHE_DIR = Path.home() / ".cache" / "network-scanner"
OUI_CACHE_FILE = CACHE_DIR / "oui.csv"

_lock = threading.Lock()
_vendor_map: dict[str, str] | None = None


def normalize_mac(mac: str) -> str:
    hex_only = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(hex_only) != 12:
        return mac.lower()
    return ":".join(hex_only[index : index + 2] for index in range(0, 12, 2))


def _prefix_key(prefix: str) -> str:
    if len(prefix) <= 6:
        body = prefix.ljust(6, "0")[:6]
        return ":".join(body[index : index + 2] for index in range(0, 6, 2))
    if len(prefix) <= 7:
        body = prefix.ljust(7, "0")[:7]
        return f"{body[:2]}:{body[2:4]}:{body[4:6]}:{body[6:7]}"
    body = prefix.ljust(9, "0")[:9]
    return f"{body[:2]}:{body[2:4]}:{body[4:6]}:{body[6:8]}:{body[8:9]}"


def _download_oui_database() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(OUI_URL, headers={"User-Agent": "network-scanner/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        OUI_CACHE_FILE.write_bytes(response.read())


def _load_vendor_map() -> dict[str, str]:
    global _vendor_map
    with _lock:
        if _vendor_map is not None:
            return _vendor_map

        if not OUI_CACHE_FILE.exists():
            try:
                _download_oui_database()
            except OSError:
                _vendor_map = {}
                return _vendor_map

        vendors: dict[str, str] = {}
        try:
            for line in OUI_CACHE_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line or line.startswith("Registry"):
                    continue
                parts = [part.strip().strip('"') for part in line.split(",", 3)]
                if len(parts) < 3:
                    continue
                registry, assignment, organization = parts[0], parts[1], parts[2]
                assignment = re.sub(r"[^0-9a-fA-F]", "", assignment).upper()
                if not assignment:
                    continue
                if registry == "MA-L":
                    key = _prefix_key(assignment[:6])
                elif registry == "MA-M":
                    key = _prefix_key(assignment[:7])
                elif registry == "MA-S":
                    key = _prefix_key(assignment[:9])
                else:
                    continue
                vendors[key] = organization
        except OSError:
            vendors = {}

        _vendor_map = vendors
        return _vendor_map


def lookup_vendor(mac: str | None) -> str | None:
    if not mac:
        return None

    vendors = _load_vendor_map()
    if not vendors:
        return None

    clean = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    for length in (9, 7, 6):
        key = _prefix_key(clean[:length])
        vendor = vendors.get(key)
        if vendor:
            return vendor
    return None


def preload_vendor_database() -> bool:
    try:
        _load_vendor_map()
        return bool(_vendor_map)
    except OSError:
        return False
