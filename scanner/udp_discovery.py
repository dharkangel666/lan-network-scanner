"""UDP service discovery for common application protocols."""

from __future__ import annotations

import asyncio
import random
import struct
from typing import Any

UDP_SERVICES: dict[int, str] = {
    53: "DNS",
    67: "DHCP",
    123: "NTP",
    161: "SNMP",
    1900: "SSDP",
}

SNMP_GET_SYS_DESCR = bytes.fromhex(
    "302902010104067075626c6963a01c0204"
    "0000000002000100020100020100300e300c06082b060102010101000500"
)


def _dns_query() -> bytes:
    transaction_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"\x07version\x04bind\x00\x00\x10\x00\x01"
    return header + question


def _ntp_request() -> bytes:
    return b"\x1b" + 47 * b"\0"


async def probe_udp_port(host: str, port: int, timeout: float = 0.75) -> bool:
    loop = asyncio.get_running_loop()
    payload = _payload_for_port(port)
    if payload is None:
        return False

    def send_receive() -> bool:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            data, _ = sock.recvfrom(4096)
            return bool(data)
        except OSError:
            return False
        finally:
            sock.close()

    return await loop.run_in_executor(None, send_receive)


def _payload_for_port(port: int) -> bytes | None:
    if port == 53:
        return _dns_query()
    if port == 123:
        return _ntp_request()
    if port == 161:
        return SNMP_GET_SYS_DESCR
    if port == 1900:
        return (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 1\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()
    return b"\0"


async def scan_udp_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 0.75,
) -> list[dict[str, Any]]:
    target_ports = ports or list(UDP_SERVICES)
    results: list[dict[str, Any]] = []
    for port in target_ports:
        if await probe_udp_port(host, port, timeout=timeout):
            results.append(
                {
                    "port": port,
                    "protocol": "udp",
                    "service": UDP_SERVICES.get(port, f"UDP {port}"),
                    "state": "open",
                    "hint": UDP_SERVICES.get(port, f"UDP {port}"),
                }
            )
    return results


def hints_from_udp_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for item in results:
        port = int(item["port"])
        hint = str(item.get("hint") or UDP_SERVICES.get(port) or f"UDP {port}")
        hints.append(
            {
                "type": f"udp/{port}",
                "name": "udp",
                "hint": hint,
                "source": "udp",
                "port": port,
                "service": item.get("service"),
                "state": item.get("state"),
            }
        )
    return hints
