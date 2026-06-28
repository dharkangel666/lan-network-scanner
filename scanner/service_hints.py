from collections.abc import Iterable

from scanner.port_info import get_port_info
from scanner.port_scanner import parse_ports

PROFILE_SOURCE = "profile"


def filter_discovered_services(services: list[dict] | None) -> list[dict]:
    """Drop saved profile port hints — profiles are scan presets, not discovered services."""
    return [
        item
        for item in (services or [])
        if str(item.get("source") or item.get("name") or "") != PROFILE_SOURCE
    ]


def refresh_host_service_fields(
    host: dict,
    *,
    scanned_ports: list[int] | None = None,
    port_results: list[dict] | None = None,
    udp_results: list[dict] | None = None,
    protocol_services: list[dict] | None = None,
) -> None:
    """Recompute Services column from discovered sources only (not port profiles)."""
    services, role = assemble_host_services(
        mdns_services=filter_discovered_services(host.get("mdns_services")),
        ssdp_services=host.get("ssdp_services"),
        udp_services=udp_results,
        scanned_ports=scanned_ports,
        protocol_services=protocol_services,
    )
    host["mdns_services"] = services
    host["device_role"] = role


PORT_HINTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "Web",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
    8888: "HTTP",
    9000: "HTTP",
    62078: "Apple sync",
}


def hint_for_port(port: int) -> str:
    if port in PORT_HINTS:
        return PORT_HINTS[port]
    info = get_port_info(port)
    service = info.get("service")
    if service and service != "unknown":
        return str(service).upper()
    return f"Port {port}"


def hints_from_ports(ports: Iterable[int], source: str) -> list[dict]:
    items: list[dict] = []
    for port in sorted({int(port) for port in ports}):
        items.append(
            {
                "type": f"tcp/{port}",
                "name": source,
                "hint": hint_for_port(port),
                "source": source,
            }
        )
    return items


def hints_from_port_spec(port_spec: str | None, source: str = "profile") -> list[dict]:
    if not port_spec:
        return []
    try:
        ports = parse_ports(port_spec)
    except ValueError:
        return []
    return hints_from_ports(ports, source=source)


def merge_service_hints(*groups: Iterable[dict]) -> list[dict]:
    merged: list[dict] = []
    seen_hints: set[str] = set()
    source_rank = {"mdns": 0, "ssdp": 1, "probe": 2, "scan": 3, "udp": 4, "profile": 5}

    flattened: list[dict] = []
    for group in groups:
        flattened.extend(group)

    flattened.sort(
        key=lambda item: source_rank.get(str(item.get("source") or item.get("name") or "unknown"), 99)
    )

    for item in flattened:
        hint = str(item.get("hint") or "").strip()
        if not hint:
            continue
        key = hint.lower()
        if key in seen_hints:
            continue
        seen_hints.add(key)
        merged.append(item)
    return merged


def summarize_device_role(services: list[dict], limit: int = 5) -> str | None:
    if not services:
        return None

    hints: list[str] = []
    seen: set[str] = set()
    profile_only = all(item.get("source") == "profile" for item in services)

    for service in services:
        hint = service.get("hint")
        if not hint or hint in seen:
            continue
        seen.add(hint)
        hints.append(hint)
        if len(hints) >= limit:
            break

    if not hints:
        return None

    role = " · ".join(hints)
    if profile_only:
        role += " (saved profile)"
    return role


def assemble_host_services(
    *,
    mdns_services: list[dict] | None = None,
    ssdp_services: list[dict] | None = None,
    udp_services: list[dict] | None = None,
    probed_ports: Iterable[int] | None = None,
    scanned_ports: Iterable[int] | None = None,
    protocol_services: Iterable[dict] | None = None,
) -> tuple[list[dict], str | None]:
    mdns = []
    for item in filter_discovered_services(mdns_services):
        mdns.append({**item, "source": item.get("source") or "mdns"})

    ssdp = []
    for item in ssdp_services or []:
        ssdp.append({**item, "source": item.get("source") or "ssdp"})

    udp = list(udp_services or [])
    protocol = list(protocol_services or [])

    probed = hints_from_ports(probed_ports or [], source="probe")
    scanned = hints_from_ports(scanned_ports or [], source="scan")

    services = merge_service_hints(mdns, ssdp, protocol, scanned, udp, probed)
    role = summarize_device_role(services)
    return services, role
