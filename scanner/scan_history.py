import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from scanner.vendor import normalize_mac

CACHE_DIR = Path.home() / ".cache" / "lan-network-scanner"
LAST_SCAN_FILE = CACHE_DIR / "last-scan.json"
KNOWN_DEVICES_FILE = CACHE_DIR / "known-devices.json"

_GENERIC_STARLINK_NAMES = frozenset(
    {
        "",
        "wlan0",
        "eth0",
        "lwip0",
        "unknown",
        "controller",
    }
)


def _normalize_ip(ip: str | None) -> str:
    if not ip:
        return ""
    try:
        return str(ipaddress.IPv4Address(str(ip).strip()))
    except ipaddress.AddressValueError:
        return str(ip).strip()


def _identity_mac(host: dict) -> str:
    mac = host.get("mac")
    if not mac:
        return ""
    hex_only = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    if len(hex_only) != 12:
        return ""
    return normalize_mac(str(mac))


def _identity_hostname(host: dict) -> str:
    hostname = str(host.get("hostname") or "").strip().lower()
    if not hostname or hostname in {"—", "-", "localhost", "_gateway"}:
        return ""
    return hostname


def _identity_starlink_name(host: dict) -> str:
    name = str(host.get("starlink_name") or "").strip()
    if not name:
        return ""
    lowered = name.lower()
    if lowered in _GENERIC_STARLINK_NAMES:
        return ""
    return lowered


def _identity_keys(host: dict) -> set[str]:
    keys: set[str] = set()
    mac = _identity_mac(host)
    if mac:
        keys.add(f"mac:{mac}")
    hostname = _identity_hostname(host)
    if hostname:
        keys.add(f"hostname:{hostname}")
    starlink = _identity_starlink_name(host)
    if starlink:
        keys.add(f"starlink:{starlink}")
    return keys


def _build_previous_indexes(
    last_scan: dict,
) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict], dict[str, dict]]:
    by_ip: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}
    by_hostname: dict[str, dict] = {}
    by_starlink: dict[str, dict] = {}

    for item in last_scan.get("hosts", []):
        ip = _normalize_ip(item.get("ip"))
        mac = _identity_mac(item)
        hostname = _identity_hostname(item)
        starlink = _identity_starlink_name(item)

        if ip:
            by_ip[ip] = item
        if mac:
            by_mac[mac] = item
        if hostname and hostname not in by_hostname:
            by_hostname[hostname] = item
        if starlink and starlink not in by_starlink:
            by_starlink[starlink] = item

    return by_ip, by_mac, by_hostname, by_starlink


def _match_previous_host(
    host: dict,
    by_ip: dict[str, dict],
    by_mac: dict[str, dict],
    by_hostname: dict[str, dict],
    by_starlink: dict[str, dict],
) -> tuple[dict | None, str | None]:
    ip = _normalize_ip(host.get("ip"))
    mac = _identity_mac(host)
    hostname = _identity_hostname(host)
    starlink = _identity_starlink_name(host)

    if mac and mac in by_mac:
        return by_mac[mac], "mac"
    if hostname and hostname in by_hostname:
        return by_hostname[hostname], "hostname"
    if starlink and starlink in by_starlink:
        return by_starlink[starlink], "starlink"
    if ip and ip in by_ip:
        previous = by_ip[ip]
        previous_mac = _identity_mac(previous)
        if not previous_mac or not mac or previous_mac == mac:
            return previous, "ip"
    return None, None


def load_known_identities() -> set[str]:
    if not KNOWN_DEVICES_FILE.exists():
        return set()
    try:
        payload = json.loads(KNOWN_DEVICES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(payload, list):
        return {str(item) for item in payload}
    return set()


def save_known_identities(known: set[str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    KNOWN_DEVICES_FILE.write_text(
        json.dumps(sorted(known), indent=2),
        encoding="utf-8",
    )


def _note_ip_change(host: dict, previous: dict, match_kind: str) -> None:
    if match_kind in {"mac", "hostname", "starlink"}:
        if _normalize_ip(previous.get("ip")) != _normalize_ip(host.get("ip")):
            host["scan_change_detail"] = "ip_changed"


def load_last_scan() -> dict | None:
    if not LAST_SCAN_FILE.exists():
        return None
    try:
        payload = json.loads(LAST_SCAN_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("hosts"), list):
        return None
    return payload


def _snapshot_host(host: dict) -> dict:
    snapshot = dict(host)
    ip = _normalize_ip(host.get("ip")) or host.get("ip")
    if ip:
        snapshot["ip"] = ip
    mac = _identity_mac(host)
    if mac:
        snapshot["mac"] = mac
    snapshot.pop("scan_change", None)
    snapshot.pop("scan_change_detail", None)
    return snapshot


_DISPLAY_HOST_KEYS = (
    "ip",
    "mac",
    "vendor",
    "hostname",
    "os",
    "os_detail",
    "is_local",
    "method",
    "connection",
    "connection_label",
    "connection_source",
    "connection_detail",
    "mdns_services",
    "device_role",
    "infra_roles",
    "infra_role_labels",
    "starlink_name",
    "starlink_band",
    "starlink_signal_dbm",
    "starlink_snr",
    "starlink_channel_mhz",
    "starlink_link_mbps",
    "scan_change",
    "scan_change_detail",
)


def _display_host(host: dict) -> dict:
    return {key: host.get(key) for key in _DISPLAY_HOST_KEYS if key in host}


def _public_summary(summary: dict | None) -> dict | None:
    if not summary:
        return None
    return {
        key: summary[key]
        for key in (
            "first_scan",
            "new_count",
            "seen_count",
            "disappeared",
            "previous_scan_at",
            "infrastructure",
            "starlink",
            "ssdp_hosts",
        )
        if key in summary
    }


def annotate_scan_changes(hosts: list[dict], last_scan: dict | None) -> dict:
    known_identities = load_known_identities()

    if last_scan is None:
        for host in hosts:
            host["scan_change"] = None
        return {
            "first_scan": True,
            "new_count": 0,
            "seen_count": len(hosts),
            "disappeared": [],
            "previous_scan_at": None,
        }

    by_ip, by_mac, by_hostname, by_starlink = _build_previous_indexes(last_scan)

    current_ips: set[str] = set()
    current_macs: set[str] = set()
    current_hostnames: set[str] = set()
    current_starlink_names: set[str] = set()

    new_count = 0
    seen_count = 0

    for host in hosts:
        previous, match_kind = _match_previous_host(
            host,
            by_ip,
            by_mac,
            by_hostname,
            by_starlink,
        )
        ip = _normalize_ip(host.get("ip"))
        mac = _identity_mac(host)
        hostname = _identity_hostname(host)
        starlink = _identity_starlink_name(host)

        if ip:
            current_ips.add(ip)
        if mac:
            current_macs.add(mac)
        if hostname:
            current_hostnames.add(hostname)
        if starlink:
            current_starlink_names.add(starlink)

        if previous is not None:
            host["scan_change"] = "seen"
            seen_count += 1
            _note_ip_change(host, previous, match_kind or "")
            continue

        if _identity_keys(host) & known_identities:
            host["scan_change"] = "seen"
            host["scan_change_detail"] = "known_device"
            seen_count += 1
            continue

        host["scan_change"] = "new"
        new_count += 1

    disappeared = []
    for item in last_scan.get("hosts", []):
        ip = _normalize_ip(item.get("ip"))
        mac = _identity_mac(item)
        hostname = _identity_hostname(item)
        starlink = _identity_starlink_name(item)

        if ip and ip in current_ips:
            continue
        if mac and mac in current_macs:
            continue
        if hostname and hostname in current_hostnames:
            continue
        if starlink and starlink in current_starlink_names:
            continue

        disappeared.append(
            {
                "ip": ip or item.get("ip"),
                "mac": mac or item.get("mac"),
                "hostname": item.get("hostname"),
                "vendor": item.get("vendor"),
            }
        )

    disappeared.sort(key=lambda item: _normalize_ip(item.get("ip")) or str(item.get("ip") or ""))

    return {
        "first_scan": False,
        "new_count": new_count,
        "seen_count": seen_count,
        "disappeared": disappeared,
        "previous_scan_at": last_scan.get("scanned_at"),
    }


def save_scan(hosts: list[dict], network: str | None, summary: dict | None = None) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "scanned_at": datetime.now(UTC).isoformat(),
        "network": network,
        "hosts": [_snapshot_host(host) for host in hosts],
        "display_hosts": [_display_host(host) for host in hosts],
        "summary": _public_summary(summary),
    }
    LAST_SCAN_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_cached_discovery() -> dict | None:
    last_scan = load_last_scan()
    if last_scan is None:
        return None

    display_hosts = last_scan.get("display_hosts")
    if not isinstance(display_hosts, list) or not display_hosts:
        return None

    return {
        "scanned_at": last_scan.get("scanned_at"),
        "network": last_scan.get("network"),
        "hosts": display_hosts,
        "summary": last_scan.get("summary"),
    }


def finalize_scan(hosts: list[dict], network: str | None) -> dict:
    last_scan = load_last_scan()
    summary = annotate_scan_changes(hosts, last_scan)
    save_scan(hosts, network, summary)

    known_identities = load_known_identities()
    if not KNOWN_DEVICES_FILE.exists() and last_scan:
        for host in last_scan.get("hosts", []):
            if isinstance(host, dict):
                known_identities.update(_identity_keys(host))
    for host in hosts:
        known_identities.update(_identity_keys(host))
    save_known_identities(known_identities)

    return summary
