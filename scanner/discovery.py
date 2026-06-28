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
from scanner.network import LocalNetwork, get_local_network, resolve_hostname
from scanner.os_detect import OsDetection, detect_os
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
    }


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

    found: list[dict] = []
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
        found.append(host)
        if on_host:
            on_host(host)

    return found


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
            await discover_hosts(
                network=network,
                concurrency=concurrency,
                on_host=on_host,
                on_status=on_status,
            )
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
