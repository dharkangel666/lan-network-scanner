import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.vendor import normalize_mac

CACHE_DIR = Path.home() / ".cache" / "lan-network-scanner"
LAST_SCAN_FILE = CACHE_DIR / "last-scan.json"


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
    return normalize_mac(str(mac))


def _identity_hostname(host: dict) -> str:
    hostname = str(host.get("hostname") or "").strip().lower()
    if not hostname or hostname in {"—", "-", "localhost", "_gateway"}:
        return ""
    return hostname


def _build_previous_indexes(last_scan: dict) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    by_ip: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}
    by_hostname: dict[str, dict] = {}

    for item in last_scan.get("hosts", []):
        ip = _normalize_ip(item.get("ip"))
        mac = _identity_mac(item)
        hostname = _identity_hostname(item)

        if ip:
            by_ip[ip] = item
        if mac:
            by_mac[mac] = item
        if hostname and hostname not in by_hostname:
            by_hostname[hostname] = item

    return by_ip, by_mac, by_hostname


def _match_previous_host(
    host: dict,
    by_ip: dict[str, dict],
    by_mac: dict[str, dict],
    by_hostname: dict[str, dict],
) -> tuple[dict | None, str | None]:
    ip = _normalize_ip(host.get("ip"))
    mac = _identity_mac(host)
    hostname = _identity_hostname(host)

    if ip and ip in by_ip:
        return by_ip[ip], "ip"
    if mac and mac in by_mac:
        return by_mac[mac], "mac"
    if hostname and hostname in by_hostname:
        return by_hostname[hostname], "hostname"
    return None, None


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
    return {
        "ip": _normalize_ip(host.get("ip")) or host.get("ip"),
        "mac": _identity_mac(host) or host.get("mac"),
        "vendor": host.get("vendor"),
        "hostname": host.get("hostname"),
        "connection_label": host.get("connection_label"),
        "os": host.get("os"),
    }


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
        )
        if key in summary
    }


def annotate_scan_changes(hosts: list[dict], last_scan: dict | None) -> dict:
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

    by_ip, by_mac, by_hostname = _build_previous_indexes(last_scan)

    current_ips: set[str] = set()
    current_macs: set[str] = set()
    current_hostnames: set[str] = set()

    new_count = 0
    seen_count = 0

    for host in hosts:
        previous, match_kind = _match_previous_host(host, by_ip, by_mac, by_hostname)
        ip = _normalize_ip(host.get("ip"))
        mac = _identity_mac(host)
        hostname = _identity_hostname(host)

        if ip:
            current_ips.add(ip)
        if mac:
            current_macs.add(mac)
        if hostname:
            current_hostnames.add(hostname)

        if previous is not None:
            host["scan_change"] = "seen"
            seen_count += 1
            if match_kind == "mac" and _normalize_ip(previous.get("ip")) != ip:
                host["scan_change_detail"] = "ip_changed"
            elif match_kind == "hostname" and _normalize_ip(previous.get("ip")) != ip:
                host["scan_change_detail"] = "ip_changed"
            continue

        host["scan_change"] = "new"
        new_count += 1

    disappeared = []
    for item in last_scan.get("hosts", []):
        ip = _normalize_ip(item.get("ip"))
        mac = _identity_mac(item)
        hostname = _identity_hostname(item)

        if ip and ip in current_ips:
            continue
        if mac and mac in current_macs:
            continue
        if hostname and hostname in current_hostnames:
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
    return summary
