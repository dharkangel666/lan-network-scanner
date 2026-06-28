import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class LocalNetwork:
    interface: str
    address: ipaddress.IPv4Address
    network: ipaddress.IPv4Network


def get_default_route_interface() -> str | None:
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    match = re.search(r"dev (\S+)", output)
    return match.group(1) if match else None


def get_local_network() -> LocalNetwork | None:
    interface = get_default_route_interface()
    if not interface:
        return _fallback_local_network()

    try:
        output = subprocess.check_output(["ip", "-4", "addr", "show", interface], text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return _fallback_local_network()

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("inet "):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            iface = ipaddress.IPv4Interface(parts[1])
        except ValueError:
            continue
        return LocalNetwork(
            interface=interface,
            address=iface.ip,
            network=iface.network,
        )

    return _fallback_local_network()


def _fallback_local_network() -> LocalNetwork | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        local_ip = ipaddress.IPv4Address(sock.getsockname()[0])
    except OSError:
        return None
    finally:
        sock.close()

    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return LocalNetwork(interface="unknown", address=local_ip, network=network)



def resolve_hostname(ip: str) -> str | None:
    from scanner.mdns import resolve_mdns_hostname

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    return resolve_mdns_hostname(ip)
