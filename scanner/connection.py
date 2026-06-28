import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scanner.network import LocalNetwork, get_default_route_interface
from scanner.vendor import normalize_mac

logger = logging.getLogger(__name__)

CACHE_DIR = Path.home() / ".cache" / "lan-network-scanner"
STARLINK_LOG = CACHE_DIR / "starlink.log"
DISH_PROTOSET_FILE = CACHE_DIR / "dish.protoset"
ROUTER_PROTOSET_FILE = CACHE_DIR / "router.protoset"
BUNDLED_PROTOSET_FILE = Path(__file__).resolve().parent / "starlink" / "dish.protoset"
PROJECT_GRPCURL = Path(__file__).resolve().parent.parent / ".bin" / "grpcurl"

DISH_HOST = "192.168.100.1"
DISH_PORT = 9200
ROUTER_PORT = 9000

WIFI_INTERFACE_PREFIXES = ("wlan", "wlp", "wifi", "wlx")
ETHERNET_INTERFACE_PREFIXES = ("eth", "enp", "eno", "ens", "enx")

WIFI_VENDOR_KEYWORDS = (
    "espressif",
    "tuya",
    "shenzhen",
    "iot",
    "ring",
    "wyze",
    "sonos",
    "roku",
    "google",
    "nest",
    "amazon",
    "echostar",
    "philips",
    "lifx",
    "tp-link",
    "tplink",
    "meross",
    "govee",
    "eero",
    "ubiquiti",
    "raspberry pi trading",
)

ETHERNET_VENDOR_KEYWORDS = (
    "synology",
    "qnap",
    "netgear",
    "microchip",
    "realtek semiconductor",
    "intel corporate",
    "dell",
    "hewlett packard",
    "lenovo",
    "super micro",
    "asustek",
    "vmware",
    "proxmox",
)

REQUEST_PAYLOADS = (
    '{"wifiGetClients":{}}',
    '{"wifi_get_clients":{}}',
)

ROUTER_CANDIDATES = (
    "192.168.1.1",
)


@dataclass(frozen=True)
class ConnectionInfo:
    connection: str
    label: str
    source: str
    detail: str | None = None


@dataclass(frozen=True)
class StarlinkClientRecord:
    connection: ConnectionInfo
    name: str | None = None
    ip: str | None = None
    mac: str | None = None
    signal_dbm: int | None = None
    snr: int | None = None
    channel_width_mhz: int | None = None
    role: str | None = None
    link_rate_mbps: float | None = None


@dataclass(frozen=True)
class StarlinkClientMap:
    by_mac: dict[str, StarlinkClientRecord]
    by_ip: dict[str, StarlinkClientRecord]
    records: tuple[StarlinkClientRecord, ...] = ()
    router_host: str | None = None
    client_count: int = 0
    error: str | None = None
    grpcurl_path: str | None = None


def classify_interface(interface: str | None) -> ConnectionInfo | None:
    if not interface or interface == "unknown":
        return None

    name = interface.lower()
    if name.startswith(WIFI_INTERFACE_PREFIXES):
        return ConnectionInfo("wifi", "Wi-Fi", "local", interface)
    if name.startswith(ETHERNET_INTERFACE_PREFIXES):
        return ConnectionInfo("ethernet", "Ethernet", "local", interface)
    return None


def _guess_from_vendor(vendor: str | None) -> ConnectionInfo | None:
    if not vendor:
        return None

    lowered = vendor.lower()
    if any(keyword in lowered for keyword in WIFI_VENDOR_KEYWORDS):
        return ConnectionInfo("wifi", "Wi-Fi (guess)", "guess", vendor)
    if any(keyword in lowered for keyword in ETHERNET_VENDOR_KEYWORDS):
        return ConnectionInfo("ethernet", "Ethernet (guess)", "guess", vendor)
    return None


def _parse_starlink_iface(value: object) -> ConnectionInfo | None:
    if value is None:
        return None

    if isinstance(value, int):
        if value == 1:
            return ConnectionInfo("ethernet", "Ethernet", "starlink", "Wired")
        if value == 2:
            return ConnectionInfo("wifi", "Wi-Fi", "starlink", "2.4 GHz")
        if value == 3:
            return ConnectionInfo("wifi", "Wi-Fi", "starlink", "5 GHz")
        return None

    text = str(value).upper()
    if text in {"ETH", "1", "INTERFACE_ETH"} or text.endswith("_ETH"):
        return ConnectionInfo("ethernet", "Ethernet", "starlink", "Wired")
    if "RF_2" in text or "2GHZ" in text or text == "2":
        return ConnectionInfo("wifi", "Wi-Fi", "starlink", "2.4 GHz")
    if "RF_5" in text or "5GHZ" in text or text == "3":
        return ConnectionInfo("wifi", "Wi-Fi", "starlink", "5 GHz")
    return None


def _extract_starlink_clients(payload: object) -> list[dict]:
    if isinstance(payload, list):
        clients: list[dict] = []
        for item in payload:
            clients.extend(_extract_starlink_clients(item))
        return clients

    if not isinstance(payload, dict):
        return []

    for key in ("clients", "client"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    for value in payload.values():
        if isinstance(value, dict):
            found = _extract_starlink_clients(value)
            if found:
                return found
        if isinstance(value, list):
            found = _extract_starlink_clients(value)
            if found:
                return found
    return []


def normalize_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    return str(ip).strip()


def _coerce_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_float(value: object) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_starlink_client(client: dict) -> StarlinkClientRecord | None:
    connection = _parse_starlink_iface(client.get("iface") or client.get("interface"))
    if connection is None:
        return None

    mac_raw = client.get("macAddress") or client.get("mac_address") or client.get("mac")
    ip_raw = client.get("ipAddress") or client.get("ip_address") or client.get("ip")
    mac = normalize_mac(str(mac_raw)) if mac_raw else None
    ip = normalize_ip(str(ip_raw)) if ip_raw else None

    rx_stats = client.get("rxStats") if isinstance(client.get("rxStats"), dict) else {}
    link_rate = _coerce_float(rx_stats.get("rateMbps"))

    return StarlinkClientRecord(
        connection=connection,
        name=str(client["name"]).strip() if client.get("name") else None,
        ip=ip,
        mac=mac,
        signal_dbm=_coerce_int(client.get("signalStrength")),
        snr=_coerce_int(client.get("snr")),
        channel_width_mhz=_coerce_int(client.get("channelWidth")),
        role=str(client["role"]).strip() if client.get("role") else None,
        link_rate_mbps=link_rate,
    )


def _build_starlink_client_map(records: list[StarlinkClientRecord]) -> tuple[dict[str, StarlinkClientRecord], dict[str, StarlinkClientRecord]]:
    by_mac: dict[str, StarlinkClientRecord] = {}
    by_ip: dict[str, StarlinkClientRecord] = {}
    for record in records:
        if record.mac:
            by_mac[record.mac] = record
        if record.ip:
            by_ip[record.ip] = record
    return by_mac, by_ip


def _parse_starlink_response(raw: str) -> tuple[dict[str, StarlinkClientRecord], dict[str, StarlinkClientRecord], tuple[StarlinkClientRecord, ...]]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}, {}, ()

    status = payload.get("status")
    if isinstance(status, dict):
        code = str(status.get("code", "")).upper()
        message = status.get("message") or status.get("details")
        if code and code not in {"OK", "0", "SUCCESS"}:
            raise RuntimeError(message or code)

    records: list[StarlinkClientRecord] = []
    for client in _extract_starlink_clients(payload):
        record = _parse_starlink_client(client)
        if record is not None:
            records.append(record)

    by_mac, by_ip = _build_starlink_client_map(records)
    return by_mac, by_ip, tuple(records)


def lookup_starlink_client(
    ip: str,
    mac: str | None,
    starlink_clients: StarlinkClientMap,
) -> StarlinkClientRecord | None:
    host_ip = normalize_ip(ip)
    if host_ip:
        record = starlink_clients.by_ip.get(host_ip)
        if record is not None:
            return record

    if mac:
        record = starlink_clients.by_mac.get(normalize_mac(mac))
        if record is not None:
            return record

    return None


def starlink_record_to_host_fields(record: StarlinkClientRecord) -> dict:
    fields = {
        "starlink_name": record.name,
        "starlink_signal_dbm": record.signal_dbm,
        "starlink_snr": record.snr,
        "starlink_band": record.connection.detail,
        "starlink_channel_mhz": record.channel_width_mhz,
        "starlink_role": record.role,
        "starlink_link_mbps": record.link_rate_mbps,
    }
    return {key: value for key, value in fields.items() if value is not None}


def summarize_starlink_clients(
    client_map: StarlinkClientMap,
    *,
    matched_count: int = 0,
    scanned_count: int = 0,
) -> dict:
    clients = [
        record
        for record in client_map.records
        if (record.role or "").upper() != "CONTROLLER"
    ]
    ethernet_clients = sum(1 for record in clients if record.connection.connection == "ethernet")
    wifi_clients = sum(1 for record in clients if record.connection.connection == "wifi")
    wifi_2_4ghz = sum(1 for record in clients if record.connection.detail == "2.4 GHz")
    wifi_5ghz = sum(1 for record in clients if record.connection.detail == "5 GHz")
    snr_values = [record.snr for record in clients if record.snr is not None]
    signal_values = [record.signal_dbm for record in clients if record.signal_dbm is not None]

    return {
        "available": client_map.client_count > 0 and client_map.error is None,
        "router_host": client_map.router_host,
        "client_count": len(clients),
        "ethernet_clients": ethernet_clients,
        "wifi_clients": wifi_clients,
        "wifi_2_4ghz": wifi_2_4ghz,
        "wifi_5ghz": wifi_5ghz,
        "avg_snr": round(sum(snr_values) / len(snr_values), 1) if snr_values else None,
        "avg_signal_dbm": round(sum(signal_values) / len(signal_values), 1) if signal_values else None,
        "weak_signal_clients": sum(
            1 for record in clients if record.signal_dbm is not None and record.signal_dbm < -70
        ),
        "matched_in_scan": matched_count,
        "scanned_hosts": scanned_count,
        "error": client_map.error,
    }


def _grpcurl_runs(path: str) -> bool:
    try:
        completed = subprocess.run(
            [path, "-version"],
            capture_output=True,
            timeout=3,
            check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def find_grpcurl() -> str | None:
    if PROJECT_GRPCURL.is_file():
        path = str(PROJECT_GRPCURL)
        if _grpcurl_runs(path):
            return path

    found = shutil.which("grpcurl")
    if found and _grpcurl_runs(found):
        return found

    for candidate in ("/usr/bin/grpcurl", "/usr/local/bin/grpcurl", "/snap/bin/grpcurl"):
        if Path(candidate).is_file() and _grpcurl_runs(candidate):
            return candidate
    return None


def get_default_gateway() -> str | None:
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None

    match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", output)
    return match.group(1) if match else None


def _router_hosts() -> list[str]:
    hosts: list[str] = []
    gateway = get_default_gateway()
    if gateway:
        hosts.append(gateway)
    for candidate in ROUTER_CANDIDATES:
        if candidate not in hosts:
            hosts.append(candidate)
    return hosts


def _log_starlink(message: str) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with STARLINK_LOG.open("a", encoding="utf-8") as handle:
        handle.write(message.rstrip() + "\n")


def _export_protoset(grpcurl: str, host: str, port: int, destination: Path, timeout: float) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()

    command = [
        grpcurl,
        "-plaintext",
        "-max-time",
        str(max(1, int(timeout))),
        "-protoset-out",
        str(destination),
        f"{host}:{port}",
        "describe",
        "SpaceX.API.Device.Device",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        _log_starlink(f"protoset export exception for {host}:{port}: {exc}")
        return False

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "protoset export failed").strip()
        _log_starlink(f"protoset export failed for {host}:{port}: {detail}")
        return False

    return destination.exists() and destination.stat().st_size > 0


def _resolve_protoset(grpcurl: str, timeout: float) -> Path | None:
    candidates: list[Path] = []
    for path in (DISH_PROTOSET_FILE, ROUTER_PROTOSET_FILE, BUNDLED_PROTOSET_FILE):
        if path.exists() and path.stat().st_size > 0 and path not in candidates:
            candidates.append(path)

    if candidates:
        return candidates[0]

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if _export_protoset(grpcurl, DISH_HOST, DISH_PORT, DISH_PROTOSET_FILE, timeout):
        return DISH_PROTOSET_FILE

    gateway = get_default_gateway() or "192.168.1.1"
    if _export_protoset(grpcurl, gateway, ROUTER_PORT, ROUTER_PROTOSET_FILE, timeout):
        return ROUTER_PROTOSET_FILE

    return None


def _ensure_protoset(grpcurl: str, host: str, timeout: float) -> Path | None:
    del host  # protoset is shared; router host is used only for the RPC call
    return _resolve_protoset(grpcurl, timeout)


def _run_grpcurl(
    grpcurl: str,
    host: str,
    payload: str,
    timeout: float,
    protoset: Path | None,
) -> tuple[str, str]:
    command = [
        grpcurl,
        "-plaintext",
        "-max-time",
        str(max(1, int(timeout))),
        "-d",
        payload,
    ]
    if protoset is not None:
        command.extend(["-protoset", str(protoset)])
    command.extend([f"{host}:{ROUTER_PORT}", "SpaceX.API.Device.Device/Handle"])

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "grpcurl failed").strip()
        raise RuntimeError(detail)
    return completed.stdout, completed.stderr


def fetch_starlink_clients(router_host: str | None = None, timeout: float = 5.0) -> StarlinkClientMap:
    grpcurl = find_grpcurl()
    if grpcurl is None:
        return StarlinkClientMap({}, {}, error="grpcurl not found in PATH")

    hosts = [router_host] if router_host else _router_hosts()
    last_error = "Starlink router API unreachable"

    protoset = _resolve_protoset(grpcurl, timeout)
    if protoset is None:
        return StarlinkClientMap(
            {},
            {},
            error="Missing Starlink protoset — run Starlink Setup while connected to your Starlink LAN",
            grpcurl_path=grpcurl,
        )

    for host in hosts:
        if not host:
            continue

        for payload in REQUEST_PAYLOADS:
            try:
                stdout, stderr = _run_grpcurl(grpcurl, host, payload, timeout, protoset)
                by_mac, by_ip, records = _parse_starlink_response(stdout)
                if by_mac or by_ip:
                    client_count = len(records)
                    _log_starlink(
                        f"OK {host}:{ROUTER_PORT} payload={payload} clients={client_count} stderr={stderr.strip()!r}"
                    )
                    return StarlinkClientMap(
                        by_mac=by_mac,
                        by_ip=by_ip,
                        records=records,
                        router_host=host,
                        client_count=client_count,
                        grpcurl_path=grpcurl,
                    )
                last_error = "Starlink returned no clients (empty Wi-Fi/Ethernet list)"
            except RuntimeError as exc:
                last_error = str(exc)
                _log_starlink(f"FAIL {host}:{ROUTER_PORT} payload={payload}: {exc}")

    return StarlinkClientMap({}, {}, error=last_error, grpcurl_path=grpcurl)


def get_starlink_status() -> dict:
    grpcurl = find_grpcurl()
    protoset = _resolve_protoset(grpcurl, 5.0) if grpcurl else None
    result = fetch_starlink_clients()
    summary = summarize_starlink_clients(result)
    return {
        **summary,
        "grpcurl_path": result.grpcurl_path,
        "protoset_path": str(protoset) if protoset else None,
        "log_file": str(STARLINK_LOG),
    }


def resolve_connection(
    *,
    ip: str,
    mac: str | None,
    vendor: str | None,
    is_local: bool,
    local: LocalNetwork,
    starlink_clients: StarlinkClientMap,
) -> ConnectionInfo:
    if is_local:
        local_info = classify_interface(local.interface) or classify_interface(get_default_route_interface())
        if local_info:
            return local_info

    starlink_record = lookup_starlink_client(ip, mac, starlink_clients)
    if starlink_record is not None:
        return starlink_record.connection

    guessed = _guess_from_vendor(vendor)
    if guessed:
        return guessed

    gateway = get_default_gateway()
    if gateway and ip == gateway:
        return ConnectionInfo("ethernet", "Router", "guess", "Likely wired gateway")

    return ConnectionInfo("unknown", "Unknown", "unknown")


def apply_connection_to_host(
    host: dict,
    *,
    local: LocalNetwork,
    starlink_clients: StarlinkClientMap,
) -> bool:
    starlink_record = lookup_starlink_client(host["ip"], host.get("mac"), starlink_clients)
    info = resolve_connection(
        ip=host["ip"],
        mac=host.get("mac"),
        vendor=host.get("vendor"),
        is_local=host.get("is_local", False),
        local=local,
        starlink_clients=starlink_clients,
    )
    host.update(connection_to_dict(info))
    if starlink_record is not None:
        host.update(starlink_record_to_host_fields(starlink_record))
        return True
    return info.source == "starlink"


def connection_to_dict(info: ConnectionInfo) -> dict:
    return {
        "connection": info.connection,
        "connection_label": info.label,
        "connection_source": info.source,
        "connection_detail": info.detail,
    }


def enrich_hosts_with_connection(hosts: list[dict], local: LocalNetwork) -> list[dict]:
    starlink_clients = fetch_starlink_clients()
    enriched: list[dict] = []
    for host in hosts:
        updated = dict(host)
        apply_connection_to_host(updated, local=local, starlink_clients=starlink_clients)
        enriched.append(updated)
    return enriched
