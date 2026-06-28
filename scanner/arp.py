import re
import subprocess
from collections.abc import Callable

from scanner.network import LocalNetwork
from scanner.vendor import normalize_mac


class ArpPermissionError(PermissionError):
    pass


def get_interface_mac(interface: str) -> str | None:
    try:
        output = subprocess.check_output(["ip", "link", "show", interface], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    match = re.search(r"link/ether (\S+)", output)
    if not match:
        return None
    return normalize_mac(match.group(1))


def read_neighbor_table(interface: str) -> dict[str, str]:
    try:
        output = subprocess.check_output(["ip", "neigh", "show", "dev", interface], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}

    neighbors: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] != "lladdr":
            continue
        ip, mac = parts[0], parts[2]
        if mac in {"FAILED", "INCOMPLETE"} or ":" not in mac:
            continue
        neighbors[ip] = normalize_mac(mac)
    return neighbors


def arp_scan_scapy(local: LocalNetwork, timeout: float = 2.0) -> dict[str, str]:
    try:
        from scapy.all import ARP, Ether, conf, srp
    except ImportError as exc:
        raise RuntimeError("scapy is not installed") from exc

    conf.verb = 0
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(local.network))

    try:
        answered, _ = srp(packet, timeout=timeout, iface=local.interface, retry=1)
    except PermissionError as exc:
        raise ArpPermissionError("ARP scan requires raw socket access") from exc

    results: dict[str, str] = {}
    for _, response in answered:
        results[response.psrc] = normalize_mac(response.hwsrc)
    return results


def merge_mac_tables(*tables: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for table in tables:
        merged.update(table)
    return merged


def enrich_with_local_host(
    hosts: dict[str, str],
    local: LocalNetwork,
) -> dict[str, str]:
    enriched = dict(hosts)
    local_ip = str(local.address)
    if local_ip not in enriched:
        local_mac = get_interface_mac(local.interface)
        if local_mac:
            enriched[local_ip] = local_mac
    return enriched


def collect_neighbor_macs(
    local: LocalNetwork,
    on_progress: Callable[[str], None] | None = None,
) -> dict[str, str]:
    if on_progress:
        on_progress("Reading ARP neighbor table...")
    neighbors = read_neighbor_table(local.interface)
    return enrich_with_local_host(neighbors, local)
