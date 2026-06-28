"""SSDP / UPnP discovery via M-SEARCH."""

from __future__ import annotations

import re
import socket
from collections import defaultdict
from typing import Any

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def _parse_ssdp_response(payload: str, source_ip: str) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    for line in payload.split("\r\n"):
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    location = headers.get("location")
    usn = headers.get("usn")
    st = headers.get("st") or headers.get("nt")
    server = headers.get("server")
    if not usn and not st and not server:
        return None

    friendly = usn.split("::")[0] if usn and "::" in usn else (usn or st or "UPnP device")
    device_type = st or ""
    if device_type.startswith("urn:"):
        parts = device_type.split(":")
        if len(parts) >= 4:
            device_type = parts[3]

    return {
        "type": st or "ssdp:device",
        "name": friendly[:120],
        "hint": _friendly_hint(device_type, server),
        "source": "ssdp",
        "usn": usn,
        "server": server,
        "location": location,
        "ip": source_ip,
    }


def _friendly_hint(device_type: str, server: str | None) -> str:
    lowered = (device_type or "").lower()
    mapping = {
        "mediarenderer": "Media renderer",
        "mediaserver": "Media server",
        "internetgatewaydevice": "Router / gateway",
        "wandevice": "WAN device",
        "wancic": "WAN connection",
        "printer": "Printer",
        "scanner": "Scanner",
        "binarylight": "Smart light",
        "hue": "Philips Hue",
    }
    for key, label in mapping.items():
        if key in lowered:
            return label
    if server:
        return server.split("/")[0][:48]
    if device_type:
        return device_type.replace("_", " ")[:48]
    return "UPnP"


def browse_ssdp(timeout: float = 3.0) -> dict[str, list[dict[str, Any]]]:
    by_ip: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.bind(("", 0))
        ttl = socket.IP_MULTICAST_TTL
        sock.setsockopt(socket.IPPROTO_IP, ttl, 2)
        sock.sendto(MSEARCH, (SSDP_ADDR, SSDP_PORT))

        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                break
            source_ip = address[0]
            text = data.decode("utf-8", errors="ignore")
            if not text.startswith("HTTP/"):
                continue
            entry = _parse_ssdp_response(text, source_ip)
            if not entry:
                continue
            key = entry.get("usn") or entry.get("type") or entry.get("name")
            by_ip[source_ip][str(key)] = entry
    except OSError:
        return {}
    finally:
        sock.close()

    return {ip: list(entries.values()) for ip, entries in by_ip.items()}


def resolve_services_for_ip(ip: str, ssdp_by_ip: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    return list(ssdp_by_ip.get(ip, []))
