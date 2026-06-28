import asyncio
import platform
import re
import subprocess
from dataclasses import dataclass

from scanner.port_scanner import scan_port

OS_PROBE_PORTS = [22, 23, 80, 135, 139, 443, 445, 62078, 8080]

VENDOR_OS_HINTS = {
    "Apple": "Apple macOS / iOS",
    "Microsoft": "Windows",
    "Espressif": "Embedded (ESP32)",
    "Raspberry Pi Foundation": "Linux (Raspberry Pi)",
    "Google": "Android / ChromeOS / Nest",
    "Samsung": "Android / Tizen",
    "Tuya Smart": "Embedded IoT",
    "Amazon Technologies": "Fire OS / Alexa",
    "Sonos": "Sonos (embedded Linux)",
    "Ubiquiti": "UniFi / embedded Linux",
    "ASUSTek": "Router / embedded Linux",
    "TP-Link": "Router / embedded Linux",
    "Netgear": "Router / embedded Linux",
    "Cisco": "Network appliance",
    "Hewlett Packard": "Printer / network device",
    "Brother Industries": "Printer",
    "Intel Corporate": "PC / laptop",
    "Dell": "PC / laptop",
    "Lenovo": "PC / laptop",
}


@dataclass(frozen=True)
class OsDetection:
    os: str | None
    detail: str | None = None
    confidence: str = "low"


def get_local_os() -> OsDetection:
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            values = {}
            for line in handle:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    values[key] = value.strip().strip('"')
            pretty = values.get("PRETTY_NAME")
            if pretty:
                return OsDetection(os=pretty, detail="local system", confidence="high")
            name = values.get("NAME")
            version = values.get("VERSION")
            if name:
                label = f"{name} {version}".strip()
                return OsDetection(os=label, detail="local system", confidence="high")
    except OSError:
        pass

    return OsDetection(
        os=platform.platform(aliased=True, terse=True),
        detail="local system",
        confidence="high",
    )


def _vendor_hint(vendor: str | None) -> OsDetection | None:
    if not vendor:
        return None
    for prefix, label in VENDOR_OS_HINTS.items():
        if vendor.startswith(prefix):
            return OsDetection(os=label, detail=f"vendor: {vendor}", confidence="low")
    return None


def _ping_ttl(ip: str, timeout: float = 1.0) -> int | None:
    try:
        completed = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 0.5,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    match = re.search(r"\bttl=(\d+)", completed.stdout, re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1))


def _guess_os_from_ttl(ttl: int) -> OsDetection:
    if ttl <= 32:
        return OsDetection(os="Embedded / network device", detail=f"ttl={ttl}", confidence="low")
    if ttl <= 64:
        return OsDetection(os="Linux / Unix / macOS", detail=f"ttl={ttl}", confidence="low")
    if ttl <= 128:
        return OsDetection(os="Windows", detail=f"ttl={ttl}", confidence="low")
    return OsDetection(os="Network appliance", detail=f"ttl={ttl}", confidence="low")


def _parse_ssh_banner(banner: str) -> OsDetection:
    lowered = banner.lower()
    if "ubuntu" in lowered:
        return OsDetection(os="Linux (Ubuntu)", detail=banner, confidence="high")
    if "debian" in lowered:
        return OsDetection(os="Linux (Debian)", detail=banner, confidence="high")
    if "raspbian" in lowered or "raspberry" in lowered:
        return OsDetection(os="Linux (Raspberry Pi OS)", detail=banner, confidence="high")
    if "freebsd" in lowered:
        return OsDetection(os="FreeBSD", detail=banner, confidence="high")
    if "openbsd" in lowered:
        return OsDetection(os="OpenBSD", detail=banner, confidence="high")
    if "windows" in lowered:
        return OsDetection(os="Windows", detail=banner, confidence="high")
    if "dropbear" in lowered:
        return OsDetection(os="Embedded Linux", detail=banner, confidence="medium")
    if "openssh" in lowered or "libssh" in lowered:
        return OsDetection(os="Linux / Unix", detail=banner, confidence="medium")
    return OsDetection(os="Unix-like", detail=banner, confidence="medium")


def _parse_http_server(server: str) -> OsDetection:
    lowered = server.lower()
    if "ubuntu" in lowered:
        return OsDetection(os="Linux (Ubuntu)", detail=f"Server: {server}", confidence="medium")
    if "win32" in lowered or "iis" in lowered:
        return OsDetection(os="Windows", detail=f"Server: {server}", confidence="medium")
    if "nginx" in lowered:
        return OsDetection(os="Linux / Unix", detail=f"Server: {server}", confidence="low")
    if "apache" in lowered:
        return OsDetection(os="Linux / Unix", detail=f"Server: {server}", confidence="low")
    if "lighttpd" in lowered or "uhttpd" in lowered:
        return OsDetection(os="Embedded Linux", detail=f"Server: {server}", confidence="medium")
    return OsDetection(os="Unknown", detail=f"Server: {server}", confidence="low")


async def _probe_open_ports(ip: str, ports: list[int], timeout: float = 0.35) -> list[int]:
    results = await asyncio.gather(*(scan_port(ip, port, timeout=timeout) for port in ports))
    return [port for port, is_open in zip(ports, results, strict=True) if is_open]


async def _read_ssh_banner(ip: str, timeout: float = 1.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 22), timeout=timeout)
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        text = banner.decode("utf-8", errors="ignore").strip()
        return text or None
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _read_http_server(ip: str, port: int, timeout: float = 1.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        await writer.drain()
        headers = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        match = re.search(r"^Server:\s*(.+)$", headers.decode("utf-8", errors="ignore"), re.MULTILINE | re.IGNORECASE)
        return match.group(1).strip() if match else None
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


def _pick_best(candidates: list[OsDetection]) -> OsDetection | None:
    if not candidates:
        return None

    rank = {"high": 3, "medium": 2, "low": 1}
    return max(candidates, key=lambda item: rank.get(item.confidence, 0))


async def detect_os(
    ip: str,
    vendor: str | None = None,
    is_local: bool = False,
) -> OsDetection:
    if is_local:
        return get_local_os()

    candidates: list[OsDetection] = []

    vendor_guess = _vendor_hint(vendor)
    if vendor_guess:
        candidates.append(vendor_guess)

    ttl = await asyncio.to_thread(_ping_ttl, ip)
    if ttl is not None:
        candidates.append(_guess_os_from_ttl(ttl))

    open_ports = await _probe_open_ports(ip, OS_PROBE_PORTS)
    if 62078 in open_ports:
        candidates.append(OsDetection(os="Apple iOS / macOS", detail="port 62078 open", confidence="medium"))
    if 445 in open_ports or 135 in open_ports or 139 in open_ports:
        candidates.append(OsDetection(os="Windows", detail="SMB/RPC ports open", confidence="medium"))
    if 3389 in open_ports:
        candidates.append(OsDetection(os="Windows", detail="RDP open", confidence="high"))

    if 22 in open_ports:
        banner = await _read_ssh_banner(ip)
        if banner:
            candidates.append(_parse_ssh_banner(banner))
        else:
            candidates.append(OsDetection(os="Linux / Unix", detail="SSH open", confidence="low"))

    if 23 in open_ports:
        candidates.append(OsDetection(os="Embedded / network device", detail="Telnet open", confidence="medium"))

    http_port = next((port for port in (80, 8080, 443) if port in open_ports), None)
    if http_port is not None:
        server = await _read_http_server(ip, http_port)
        if server:
            candidates.append(_parse_http_server(server))

    best = _pick_best(candidates)
    if best is None:
        return OsDetection(os=None, detail=None, confidence="low")
    return best
