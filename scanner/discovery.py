import asyncio
import ipaddress
from collections.abc import AsyncIterator, Callable

from scanner.arp import (
    ArpPermissionError,
    arp_scan_scapy,
    enrich_with_local_host,
    merge_mac_tables,
    read_neighbor_table,
)
from scanner.connection import apply_connection_to_host, fetch_starlink_clients, summarize_starlink_clients
from scanner.mdns_services import browse_mdns_services, resolve_services_for_ip
from scanner.network import LocalNetwork, get_local_network, resolve_hostname
from scanner.os_detect import OsDetection, detect_os
from scanner.port_results import get_recorded_ports, get_recorded_results, get_recorded_udp_results
from scanner.scan_history import _identity_mac, finalize_scan, load_last_scan
from scanner.service_graph import protocol_service_hints
from scanner.infrastructure import identify_infrastructure
from scanner.service_hints import assemble_host_services
from scanner.ssdp_discovery import browse_ssdp, resolve_services_for_ip
from scanner.udp_discovery import hints_from_udp_results
from scanner.vendor import lookup_vendor, preload_vendor_database


async def ping_host(ip: str, timeout: float = 1.0) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "ping",
        "-c",
        "1",
        "-W",
        str(max(1, int(timeout))),
        ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        return await asyncio.wait_for(proc.wait(), timeout=timeout + 0.5) == 0
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return False


def _in_subnet(ip: str, network: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in network
    except ipaddress.AddressValueError:
        return False


def build_host(
    ip: str,
    local: LocalNetwork,
    mac: str | None = None,
    method: str = "arp",
    hostname: str | None = None,
    os_name: str | None = None,
    os_detail: str | None = None,
) -> dict:
    return {
        "ip": ip,
        "mac": mac,
        "vendor": lookup_vendor(mac),
        "hostname": hostname,
        "os": os_name,
        "os_detail": os_detail,
        "is_local": ip == str(local.address),
        "method": method,
        "connection": "unknown",
        "connection_label": "Unknown",
        "connection_source": "unknown",
        "connection_detail": None,
        "mdns_services": [],
        "device_role": None,
    }


def enrich_host_services(
    host: dict,
    ip: str,
    detection: OsDetection | None,
    mdns_by_ip: dict[str, list[dict]],
    ssdp_by_ip: dict[str, list[dict]] | None = None,
) -> None:
    open_ports = tuple(getattr(detection, "open_ports", ()) or ()) if detection else ()
    ssdp_services = resolve_services_for_ip(ip, ssdp_by_ip or {})
    udp_services = hints_from_udp_results(get_recorded_udp_results(ip))
    protocol_services = protocol_service_hints(get_recorded_results(ip))
    services, role = assemble_host_services(
        mdns_services=resolve_services_for_ip(ip, mdns_by_ip),
        ssdp_services=ssdp_services,
        udp_services=udp_services,
        probed_ports=open_ports,
        scanned_ports=get_recorded_ports(ip),
        protocol_services=protocol_services,
    )
    if services:
        host["mdns_services"] = services
        host["device_role"] = role
    if ssdp_services:
        host["ssdp_services"] = ssdp_services
    if udp_services:
        host["udp_services"] = udp_services


async def reconcile_missed_hosts(
    found: list[dict],
    local: LocalNetwork,
    starlink_clients,
    mdns_by_ip: dict[str, list[dict]] | None = None,
    ssdp_by_ip: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """Re-include hosts from the previous scan that still respond but were missed by ARP."""
    last_scan = await asyncio.to_thread(load_last_scan)
    if not last_scan:
        return found

    reconciled = list(found)
    current_ips = {str(host["ip"]) for host in reconciled}
    current_macs = {_identity_mac(host) for host in reconciled}
    current_macs.discard("")

    neighbors = await asyncio.to_thread(read_neighbor_table, local.interface)
    recovered = 0

    async def recover_previous(previous: dict, ip: str, mac: str | None) -> None:
        nonlocal recovered
        if ip in current_ips or not _in_subnet(ip, local.network):
            return
        if not await ping_host(ip):
            return

        host = build_host(
            ip=ip,
            local=local,
            mac=mac or previous.get("mac"),
            method="reconcile",
            hostname=previous.get("hostname"),
            os_name=previous.get("os"),
        )
        apply_connection_to_host(host, local=local, starlink_clients=starlink_clients)
        enrich_host_services(host, ip, None, mdns_by_ip or {}, ssdp_by_ip)
        reconciled.append(host)
        current_ips.add(ip)
        identity_mac = _identity_mac(host)
        if identity_mac:
            current_macs.add(identity_mac)
        recovered += 1

    for previous in last_scan.get("hosts", []):
        ip = str(previous.get("ip") or "").strip()
        if not ip or ip in current_ips or not _in_subnet(ip, local.network):
            continue
        mac = neighbors.get(ip) or previous.get("mac")
        await recover_previous(previous, ip, mac)

    for previous in last_scan.get("hosts", []):
        mac = _identity_mac(previous)
        if not mac or mac in current_macs:
            continue
        for neighbor_ip, neighbor_mac in neighbors.items():
            if _identity_mac({"mac": neighbor_mac}) != mac:
                continue
            await recover_previous(previous, neighbor_ip, neighbor_mac)
            break

    if recovered:
        reconciled.sort(key=lambda item: ipaddress.IPv4Address(item["ip"]))

    return reconciled


async def discover_hosts(
    network: LocalNetwork | None = None,
    concurrency: int = 64,
    on_host: Callable[[dict], None] | None = None,
    on_status: Callable[[str], None] | None = None,
) -> list[dict]:
    local = network or get_local_network()
    if local is None:
        raise RuntimeError("Could not determine local network")

    await asyncio.to_thread(preload_vendor_database)

    mac_by_ip: dict[str, str] = {}
    method_by_ip: dict[str, str] = {}
    known_ips: set[str] = set()
    used_arp_scan = False

    if on_status:
        on_status("Running ARP scan...")

    try:
        arp_results = await asyncio.to_thread(arp_scan_scapy, local)
        mac_by_ip.update(arp_results)
        for ip in arp_results:
            method_by_ip[ip] = "arp"
            known_ips.add(ip)
        used_arp_scan = True
    except ArpPermissionError:
        if on_status:
            on_status("ARP scan needs raw socket access. Falling back to ping + neighbor table...")
    except Exception:
        if on_status:
            on_status("ARP scan failed. Falling back to ping + neighbor table...")

    if not used_arp_scan:
        initial_neighbors = await asyncio.to_thread(read_neighbor_table, local.interface)
        for ip, mac in initial_neighbors.items():
            if not _in_subnet(ip, local.network):
                continue
            mac_by_ip[ip] = mac
            method_by_ip.setdefault(ip, "neighbor")
            known_ips.add(ip)

        if on_status:
            on_status("Ping sweeping subnet to populate ARP cache...")
        semaphore = asyncio.Semaphore(concurrency)
        subnet_hosts = [str(ip) for ip in local.network.hosts()]

        async def probe_host(ip: str) -> None:
            async with semaphore:
                if await ping_host(ip):
                    known_ips.add(ip)
                    method_by_ip.setdefault(ip, "ping")

        await asyncio.gather(*(probe_host(ip) for ip in subnet_hosts))

        refreshed_neighbors = await asyncio.to_thread(read_neighbor_table, local.interface)
        merged_macs = merge_mac_tables(mac_by_ip, refreshed_neighbors)
        mac_by_ip = enrich_with_local_host(merged_macs, local)

        for ip, mac in refreshed_neighbors.items():
            if not _in_subnet(ip, local.network):
                continue
            if ip in known_ips and method_by_ip.get(ip) == "ping":
                method_by_ip[ip] = "ping+arp"
            elif ip not in known_ips:
                known_ips.add(ip)
                method_by_ip[ip] = "neighbor"
                mac_by_ip[ip] = mac
    else:
        mac_by_ip = enrich_with_local_host(mac_by_ip, local)
        known_ips.add(str(local.address))
        method_by_ip.setdefault(str(local.address), "local")

    if str(local.address) not in known_ips:
        known_ips.add(str(local.address))
        method_by_ip.setdefault(str(local.address), "local")

    sorted_ips = sorted(known_ips, key=lambda value: ipaddress.IPv4Address(value))
    hostname_semaphore = asyncio.Semaphore(16)

    async def resolve_host(ip: str) -> tuple[str, str | None]:
        async with hostname_semaphore:
            hostname = await asyncio.to_thread(resolve_hostname, ip)
            return ip, hostname

    hostname_results = await asyncio.gather(*(resolve_host(ip) for ip in sorted_ips))
    hostnames_by_ip = dict(hostname_results)

    if on_status:
        on_status("Detecting operating systems...")

    os_semaphore = asyncio.Semaphore(12)

    async def detect_host_os(ip: str) -> tuple[str, OsDetection]:
        async with os_semaphore:
            vendor = lookup_vendor(mac_by_ip.get(ip))
            detection = await detect_os(
                ip,
                vendor=vendor,
                is_local=ip == str(local.address),
            )
            return ip, detection

    os_results = await asyncio.gather(*(detect_host_os(ip) for ip in sorted_ips))
    os_by_ip = dict(os_results)

    if on_status:
        on_status("Browsing mDNS services...")

    mdns_by_ip = await asyncio.to_thread(browse_mdns_services)

    if on_status:
        if mdns_by_ip:
            on_status(f"Found mDNS services for {len(mdns_by_ip)} host(s)...")
        else:
            on_status("Using port probes and saved scans for service hints...")

    if on_status:
        on_status("Discovering UPnP / SSDP devices...")

    ssdp_by_ip = await asyncio.to_thread(browse_ssdp)

    if on_status:
        if ssdp_by_ip:
            on_status(f"Found UPnP services for {len(ssdp_by_ip)} host(s)...")
        else:
            on_status("No UPnP responses received.")

    if on_status:
        on_status("Detecting connection types...")

    starlink_clients = await asyncio.to_thread(fetch_starlink_clients)

    if on_status:
        if starlink_clients.client_count > 0:
            on_status(
                f"Starlink router reported {starlink_clients.client_count} clients "
                f"({len(starlink_clients.by_ip)} with IP) — matching devices..."
            )
        elif starlink_clients.error:
            on_status(f"Starlink data unavailable ({starlink_clients.error}) — using guesses")
        else:
            on_status("Starlink returned no clients — using guesses")

    found: list[dict] = []
    starlink_matched = 0
    for ip in sorted_ips:
        detection = os_by_ip.get(ip)
        host = build_host(
            ip=ip,
            local=local,
            mac=mac_by_ip.get(ip),
            method=method_by_ip.get(ip, "arp"),
            hostname=hostnames_by_ip.get(ip),
            os_name=getattr(detection, "os", None) if detection else None,
            os_detail=getattr(detection, "detail", None) if detection else None,
        )
        if apply_connection_to_host(host, local=local, starlink_clients=starlink_clients):
            starlink_matched += 1

        enrich_host_services(host, ip, detection, mdns_by_ip, ssdp_by_ip)
        found.append(host)

    if on_status and starlink_clients.client_count > 0:
        on_status(
            f"Matched {starlink_matched} of {len(found)} hosts from Starlink "
            f"({starlink_clients.client_count} on router)"
        )

    if on_status:
        on_status("Cross-checking previous scan for missed devices...")

    found = await reconcile_missed_hosts(found, local, starlink_clients, mdns_by_ip, ssdp_by_ip)

    if on_status:
        on_status("Identifying critical services (gateway, DNS, DHCP)...")

    infrastructure = await identify_infrastructure(found, local)

    gateway_ip = infrastructure.get("configured_gateway")
    if gateway_ip and not any(str(host.get("ip")) == gateway_ip for host in found):
        gateway_host = build_host(gateway_ip, local, method="configured")
        for service in infrastructure.get("services", []):
            if service.get("role") == "gateway" and service.get("ip") == gateway_ip:
                gateway_host["infra_roles"] = [
                    {
                        "role": "gateway",
                        "label": service.get("label") or "Gateway",
                        "confidence": service.get("confidence") or "configured",
                        "detail": service.get("detail"),
                    }
                ]
                gateway_host["infra_role_labels"] = "Gateway"
                break
        enrich_host_services(gateway_host, gateway_ip, None, mdns_by_ip, ssdp_by_ip)
        found.append(gateway_host)
        found.sort(key=lambda item: ipaddress.IPv4Address(item["ip"]))

    summary = await asyncio.to_thread(finalize_scan, found, str(local.network))
    summary["starlink"] = summarize_starlink_clients(
        starlink_clients,
        matched_count=starlink_matched,
        scanned_count=len(found),
    )
    summary["ssdp_hosts"] = len(ssdp_by_ip)
    summary["infrastructure"] = infrastructure

    for host in found:
        if on_host:
            on_host(host)

    return found, summary


async def stream_discovery(
    network: LocalNetwork | None = None,
    concurrency: int = 64,
) -> AsyncIterator[dict]:
    queue: asyncio.Queue[dict | None] = asyncio.Queue()

    def on_host(host: dict) -> None:
        queue.put_nowait({"event": "host", "host": host})

    def on_status(message: str) -> None:
        queue.put_nowait({"event": "status", "message": message})

    async def run_scan() -> None:
        try:
            _, summary = await discover_hosts(
                network=network,
                concurrency=concurrency,
                on_host=on_host,
                on_status=on_status,
            )
            await queue.put({"event": "summary", **summary})
        finally:
            await queue.put(None)

    task = asyncio.create_task(run_scan())
    try:
        while True:
            item = await queue.get()
            if item is None:
                break
            yield item
    finally:
        await task
