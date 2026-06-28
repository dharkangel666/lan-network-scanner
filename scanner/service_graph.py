"""Service graph and certificate inventory helpers."""

from __future__ import annotations

from typing import Any

from scanner.port_results import get_all_host_records, get_recorded_udp_results
from scanner.service_hints import assemble_host_services, filter_discovered_services
from scanner.udp_discovery import hints_from_udp_results


def _service_node(service: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": service.get("hint") or service.get("name") or "Service",
        "source": service.get("source") or "unknown",
        "type": service.get("type"),
        "name": service.get("name"),
        "detail": service.get("detail"),
    }


def build_host_service_graph(
    host: str,
    *,
    mdns_services: list[dict] | None = None,
    ssdp_services: list[dict] | None = None,
    udp_services: list[dict] | None = None,
    scanned_ports: list[int] | None = None,
    probed_ports: list[int] | None = None,
    port_results: list[dict] | None = None,
) -> dict[str, Any]:
    services, role = assemble_host_services(
        mdns_services=mdns_services,
        ssdp_services=ssdp_services,
        udp_services=udp_services,
        scanned_ports=scanned_ports,
        probed_ports=probed_ports,
        protocol_services=protocol_service_hints(port_results or []),
    )

    applications: list[dict[str, Any]] = []
    for result in port_results or []:
        probe = result.get("probe") or {}
        applications.append(
            {
                "port": result.get("port"),
                "protocol": "tcp",
                "service": result.get("service"),
                "banner": result.get("banner"),
                "probe": probe,
                "certificate": result.get("certificate") or (
                    probe if probe.get("protocol") == "tls" else None
                ),
            }
        )

    for item in udp_services or []:
        applications.append(
            {
                "port": item.get("port"),
                "protocol": "udp",
                "service": item.get("service"),
                "state": item.get("state"),
            }
        )

    return {
        "host": host,
        "role": role,
        "services": [_service_node(service) for service in services],
        "applications": applications,
    }


def protocol_service_hints(port_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for result in port_results:
        probe = result.get("probe") or {}
        summary = probe.get("summary")
        if not summary:
            continue
        port = int(result.get("port") or probe.get("port") or 0)
        hints.append(
            {
                "type": f"probe/{port}",
                "name": probe.get("protocol") or "probe",
                "hint": str(summary)[:120],
                "source": "probe",
                "detail": summary,
            }
        )
    return hints


def list_certificates() -> list[dict[str, Any]]:
    certificates: list[dict[str, Any]] = []
    for host, record in get_all_host_records().items():
        for result in record.get("results") or []:
            cert = result.get("certificate")
            if not cert and isinstance(result.get("probe"), dict):
                probe = result["probe"]
                if probe.get("protocol") == "tls":
                    cert = probe
            if not cert or not cert.get("subject"):
                continue
            certificates.append(
                {
                    "host": host,
                    "port": result.get("port") or cert.get("port"),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_after": cert.get("not_after"),
                    "expired": cert.get("expired"),
                    "hostname_match": cert.get("hostname_match"),
                    "san": cert.get("san") or [],
                }
            )
    certificates.sort(key=lambda item: (str(item.get("host")), int(item.get("port") or 0)))
    return certificates


def build_network_service_graph(hosts: list[dict[str, Any]]) -> dict[str, Any]:
    graphs: list[dict[str, Any]] = []
    for host in hosts:
        ip = str(host.get("ip") or "")
        if not ip:
            continue
        record = get_all_host_records().get(ip, {})
        udp_from_scan = hints_from_udp_results(get_recorded_udp_results(ip))
        graph = build_host_service_graph(
            ip,
            mdns_services=filter_discovered_services(host.get("mdns_services")),
            ssdp_services=host.get("ssdp_services"),
            udp_services=udp_from_scan or host.get("udp_services"),
            scanned_ports=record.get("open_ports"),
            port_results=record.get("results"),
        )
        graphs.append(graph)
    return {"hosts": graphs, "host_count": len(graphs)}
