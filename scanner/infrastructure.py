"""Identify critical LAN infrastructure: gateway, DNS, DHCP, NTP, and routers."""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import socket
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scanner.connection import get_default_gateway
from scanner.network import LocalNetwork
from scanner.udp_discovery import probe_udp_port

ROLE_LABELS = {
    "gateway": "Gateway",
    "dns": "DNS",
    "dhcp": "DHCP",
    "ntp": "NTP",
    "router": "Router",
}

LEASE_PATHS = (
    "/var/lib/dhcp/dhclient.leases",
    "/var/lib/dhcpcd/*.lease",
    "/var/lib/NetworkManager/*.lease",
    "/var/lib/dhcpcd5/*.lease",
)


@dataclass
class InfraRole:
    role: str
    label: str
    confidence: str
    detail: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "role": self.role,
            "label": self.label,
            "confidence": self.confidence,
            "detail": self.detail,
        }


@dataclass
class LocalInfraHints:
    gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    dhcp_server: str | None = None
    domain: str | None = None


@dataclass
class ProbeResults:
    dns: set[str] = field(default_factory=set)
    dhcp: set[str] = field(default_factory=set)
    ntp: set[str] = field(default_factory=set)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _read_resolv_conf() -> tuple[list[str], str | None]:
    servers: list[str] = []
    domain: str | None = None
    path = Path("/etc/resolv.conf")
    if not path.exists():
        return servers, domain

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) >= 2 and _valid_ipv4(parts[1]):
                servers.append(parts[1])
        elif stripped.startswith("domain ") and len(stripped.split()) >= 2:
            domain = stripped.split()[1]
        elif stripped.startswith("search ") and len(stripped.split()) >= 2:
            domain = domain or stripped.split()[1]

    return servers, domain


def _read_resolvectl_dns() -> list[str]:
    servers: list[str] = []
    for command in (["resolvectl", "status"], ["systemd-resolve", "--status"]):
        try:
            output = subprocess.check_output(command, text=True, timeout=3, stderr=subprocess.STDOUT)
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
        for line in output.splitlines():
            if "DNS Servers" not in line and "Current DNS Server" not in line:
                continue
            for match in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line):
                ip = match.group(1)
                if _valid_ipv4(ip):
                    servers.append(ip)
        if servers:
            break
    return servers


def _parse_lease_file(path: Path) -> tuple[str | None, list[str]]:
    dhcp_server: str | None = None
    dns_servers: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return dhcp_server, dns_servers

    for match in re.finditer(
        r"dhcp-server-identifier\s+(\d{1,3}(?:\.\d{1,3}){3})",
        text,
        flags=re.IGNORECASE,
    ):
        dhcp_server = match.group(1)

    for match in re.finditer(
        r"option\s+dhcp-server-identifier\s+(\d{1,3}(?:\.\d{1,3}){3})",
        text,
        flags=re.IGNORECASE,
    ):
        dhcp_server = match.group(1)

    for match in re.finditer(
        r"option\s+domain-name-servers\s+([^;]+)",
        text,
        flags=re.IGNORECASE,
    ):
        for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", match.group(1)):
            if _valid_ipv4(ip):
                dns_servers.append(ip)

    for match in re.finditer(
        r"option\s+routers\s+(\d{1,3}(?:\.\d{1,3}){3})",
        text,
        flags=re.IGNORECASE,
    ):
        if dhcp_server is None:
            dhcp_server = match.group(1)

    return dhcp_server, dns_servers


def _read_dhcp_lease_hints() -> tuple[str | None, list[str]]:
    dhcp_server: str | None = None
    dns_servers: list[str] = []
    for pattern in LEASE_PATHS:
        if "*" in pattern:
            parent = Path(pattern).parent
            suffix = Path(pattern).name
            if not parent.exists():
                continue
            paths = sorted(parent.glob(suffix))
        else:
            paths = [Path(pattern)]

        for path in paths:
            if not path.is_file():
                continue
            lease_dhcp, lease_dns = _parse_lease_file(path)
            if lease_dhcp and dhcp_server is None:
                dhcp_server = lease_dhcp
            dns_servers.extend(lease_dns)

    return dhcp_server, list(dict.fromkeys(dns_servers))


def read_local_infrastructure_hints() -> LocalInfraHints:
    gateway = get_default_gateway()
    resolv_dns, domain = _read_resolv_conf()
    resolvectl_dns = _read_resolvectl_dns()
    lease_dhcp, lease_dns = _read_dhcp_lease_hints()

    dns_servers: list[str] = []
    for ip in resolv_dns + resolvectl_dns + lease_dns:
        if ip in ("127.0.0.1", "127.0.0.53", "::1"):
            continue
        if _valid_ipv4(ip) and ip not in dns_servers:
            dns_servers.append(ip)

    return LocalInfraHints(
        gateway=gateway,
        dns_servers=dns_servers,
        dhcp_server=lease_dhcp or gateway,
        domain=domain,
    )


def _parse_dhcp_options(options: bytes) -> dict[int, list[bytes]]:
    parsed: dict[int, list[bytes]] = {}
    index = 0
    while index < len(options):
        code = options[index]
        if code == 255:
            break
        if code == 0:
            index += 1
            continue
        if index + 1 >= len(options):
            break
        length = options[index + 1]
        start = index + 2
        end = start + length
        if end > len(options):
            break
        parsed.setdefault(code, []).append(options[start:end])
        index = end
    return parsed


def _ip_from_option(payload: bytes) -> str | None:
    if len(payload) != 4:
        return None
    ip = socket.inet_ntoa(payload)
    return ip if _valid_ipv4(ip) else None


def dhcp_discover_server(timeout: float = 3.0) -> str | None:
    """Broadcast DHCP DISCOVER and return server identifier from OFFER/ACK."""
    transaction_id = random.randint(0, 0xFFFFFFFF)
    client_mac = bytes([0x02, 0x4C, 0x4E, 0x53]) + bytes(random.getrandbits(8) for _ in range(3))

    packet = bytearray(240)
    packet[0] = 1  # BOOTREQUEST
    packet[1] = 1  # Ethernet
    packet[2] = 6
    struct.pack_into("!I", packet, 4, transaction_id)
    struct.pack_into("!H", packet, 10, 0x8000)  # Broadcast flag
    packet[28:34] = client_mac

    options = bytearray([99, 130, 83, 99])
    options += bytes([53, 1, 1])  # DHCP Message Type: Discover
    options += bytes([55, 4, 1, 3, 6, 15])  # Parameter request list
    options += bytes([255])

    message = bytes(packet) + bytes(options)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("0.0.0.0", 68))
        except OSError:
            sock.bind(("0.0.0.0", 0))
        sock.settimeout(timeout)
        sock.sendto(message, ("255.255.255.255", 67))

        while True:
            data, addr = sock.recvfrom(4096)
            if len(data) < 240:
                continue
            if struct.unpack_from("!I", data, 4)[0] != transaction_id:
                continue
            options_start = data.find(b"\x63\x82\x53\x63")
            if options_start < 0:
                continue
            parsed = _parse_dhcp_options(data[options_start + 4 :])
            msg_types = parsed.get(53, [])
            if not msg_types or msg_types[0][0] not in {2, 5}:  # OFFER or ACK
                continue
            for option_code in (54, 50):
                for payload in parsed.get(option_code, []):
                    server = _ip_from_option(payload)
                    if server:
                        return server
            if _valid_ipv4(addr[0]) and addr[0] != "0.0.0.0":
                return addr[0]
    except OSError:
        return None
    finally:
        sock.close()

    return None


def _common_gateway_ip(network: ipaddress.IPv4Network) -> str | None:
    if network.prefixlen >= 31:
        return None
    candidate = network.network_address + 1
    if candidate in network:
        return str(candidate)
    return None


def infrastructure_candidates(
    local: LocalNetwork,
    hints: LocalInfraHints,
    hosts: list[dict],
) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(ip: str | None) -> None:
        if not ip or not _valid_ipv4(ip) or ip in seen:
            return
        try:
            if ipaddress.IPv4Address(ip) not in local.network:
                return
        except ValueError:
            return
        seen.add(ip)
        candidates.append(ip)

    add(hints.gateway)
    add(hints.dhcp_server)
    for ip in hints.dns_servers:
        add(ip)
    add(_common_gateway_ip(local.network))

    for host in hosts:
        ip = str(host.get("ip") or "")
        vendor = str(host.get("vendor") or "").lower()
        hostname = str(host.get("hostname") or "").lower()
        if re.search(r"router|gateway|starlink|netgear|tp-link|tplink|asus|unifi|eero|linksys|synology", vendor):
            add(ip)
        if re.search(r"router|gateway|pi-hole|pihole|dns", hostname):
            add(ip)
        for service in host.get("ssdp_services") or []:
            hint = str(service.get("hint") or "").lower()
            if "router" in hint or "gateway" in hint:
                add(ip)

    return candidates


async def probe_infrastructure_hosts(candidates: list[str], timeout: float = 0.75) -> ProbeResults:
    results = ProbeResults()

    async def probe_host(ip: str) -> None:
        if await probe_udp_port(ip, 53, timeout=timeout):
            results.dns.add(ip)
        if await probe_udp_port(ip, 67, timeout=timeout):
            results.dhcp.add(ip)
        if await probe_udp_port(ip, 123, timeout=timeout):
            results.ntp.add(ip)

    await asyncio.gather(*(probe_host(ip) for ip in candidates))
    return results


def _host_has_dns_service(host: dict) -> bool:
    hostname = str(host.get("hostname") or "").lower()
    if "pi-hole" in hostname or "pihole" in hostname:
        return True
    role = str(host.get("device_role") or "").lower()
    if "dns" in role or "pi-hole" in role:
        return True
    for service in (host.get("mdns_services") or []) + (host.get("ssdp_services") or []):
        hint = str(service.get("hint") or "").lower()
        name = str(service.get("name") or "").lower()
        if "dns" in hint or "dns" in name:
            return True
    return False


def _host_is_router(host: dict, gateway: str | None) -> bool:
    ip = str(host.get("ip") or "")
    if gateway and ip == gateway:
        return True
    vendor = str(host.get("vendor") or "").lower()
    if re.search(r"router|gateway|starlink|netgear|tp-link|tplink|asus|unifi|eero|linksys", vendor):
        return True
    for service in host.get("ssdp_services") or []:
        hint = str(service.get("hint") or "").lower()
        st = str(service.get("st") or service.get("type") or "").lower()
        if "gateway" in hint or "internetgatewaydevice" in st:
            return True
    return False


def annotate_host_infrastructure(
    host: dict,
    *,
    hints: LocalInfraHints,
    probes: ProbeResults,
    dhcp_discovered: str | None,
) -> list[InfraRole]:
    ip = str(host.get("ip") or "")
    roles: list[InfraRole] = []
    seen_roles: set[str] = set()

    def add(role: str, confidence: str, detail: str | None = None) -> None:
        if role in seen_roles:
            return
        seen_roles.add(role)
        roles.append(
            InfraRole(
                role=role,
                label=ROLE_LABELS.get(role, role.title()),
                confidence=confidence,
                detail=detail,
            )
        )

    if hints.gateway and ip == hints.gateway:
        add("gateway", "configured", "Default route on this machine")
    elif hints.gateway is None and ip == _common_gateway_ip_for_host(host):
        add("gateway", "inferred", "Typical gateway address (.1)")

    if ip in hints.dns_servers:
        add("dns", "configured", "Listed in system resolver config")
    if ip in probes.dns or _host_has_dns_service(host):
        add("dns", "discovered", "Responds to DNS queries or advertises DNS")

    dhcp_sources = [hints.dhcp_server, dhcp_discovered]
    if any(server and ip == server for server in dhcp_sources):
        add("dhcp", "configured" if hints.dhcp_server == ip else "discovered", "DHCP server for this LAN")
    elif ip in probes.dhcp:
        add("dhcp", "discovered", "UDP port 67 open")

    if ip in probes.ntp:
        add("ntp", "discovered", "Responds to NTP (UDP 123)")

    if _host_is_router(host, hints.gateway):
        add("router", "inferred" if ip != hints.gateway else "configured", "Router or gateway device")

    return roles


def _common_gateway_ip_for_host(host: dict) -> str | None:
    ip = str(host.get("ip") or "")
    if not _valid_ipv4(ip):
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    if parts[3] == "1":
        return ip
    return None


def apply_infrastructure_to_hosts(
    hosts: list[dict],
    *,
    hints: LocalInfraHints,
    probes: ProbeResults,
    dhcp_discovered: str | None,
) -> None:
    for host in hosts:
        roles = annotate_host_infrastructure(
            host,
            hints=hints,
            probes=probes,
            dhcp_discovered=dhcp_discovered,
        )
        host["infra_roles"] = [role.as_dict() for role in roles]
        host["infra_role_labels"] = " · ".join(role.label for role in roles) if roles else None


def build_infrastructure_summary(
    hosts: list[dict],
    *,
    hints: LocalInfraHints,
    probes: ProbeResults,
    dhcp_discovered: str | None,
) -> dict[str, Any]:
    by_role: dict[str, dict[str, Any]] = {}

    for host in hosts:
        for role in host.get("infra_roles") or []:
            role_id = str(role.get("role") or "")
            if not role_id or role_id in by_role:
                continue
            by_role[role_id] = {
                "role": role_id,
                "label": role.get("label") or ROLE_LABELS.get(role_id, role_id.title()),
                "ip": host.get("ip"),
                "hostname": host.get("hostname"),
                "vendor": host.get("vendor"),
                "confidence": role.get("confidence"),
                "detail": role.get("detail"),
            }

    def fallback_ip(role: str, ip: str | None) -> None:
        if role in by_role or not ip:
            return
        by_role[role] = {
            "role": role,
            "label": ROLE_LABELS.get(role, role.title()),
            "ip": ip,
            "hostname": None,
            "vendor": None,
            "confidence": "configured",
            "detail": "From local network configuration (host not seen in scan)",
        }

    fallback_ip("gateway", hints.gateway)
    if hints.dns_servers:
        fallback_ip("dns", hints.dns_servers[0])
    fallback_ip("dhcp", hints.dhcp_server or dhcp_discovered)

    priority = ("gateway", "router", "dns", "dhcp", "ntp")
    services = [by_role[key] for key in priority if key in by_role]

    return {
        "domain": hints.domain,
        "configured_dns": hints.dns_servers,
        "configured_gateway": hints.gateway,
        "configured_dhcp": hints.dhcp_server,
        "dhcp_discovered": dhcp_discovered,
        "probed_dns": sorted(probes.dns),
        "probed_dhcp": sorted(probes.dhcp),
        "probed_ntp": sorted(probes.ntp),
        "services": services,
        "service_count": len(services),
    }


async def identify_infrastructure(
    hosts: list[dict],
    local: LocalNetwork,
    *,
    probe_timeout: float = 0.75,
    dhcp_timeout: float = 3.0,
) -> dict[str, Any]:
    hints = await asyncio.to_thread(read_local_infrastructure_hints)
    candidates = infrastructure_candidates(local, hints, hosts)

    dhcp_discovered, probes = await asyncio.gather(
        asyncio.to_thread(dhcp_discover_server, dhcp_timeout),
        probe_infrastructure_hosts(candidates, timeout=probe_timeout),
    )

    apply_infrastructure_to_hosts(
        hosts,
        hints=hints,
        probes=probes,
        dhcp_discovered=dhcp_discovered,
    )
    return build_infrastructure_summary(
        hosts,
        hints=hints,
        probes=probes,
        dhcp_discovered=dhcp_discovered,
    )
