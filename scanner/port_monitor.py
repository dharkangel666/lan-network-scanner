import asyncio
import subprocess
import time
from collections.abc import AsyncIterator

from scanner.capabilities import can_use_raw_sockets
from scanner.network import get_local_network


async def probe_port(host: str, port: int, timeout: float = 1.0) -> dict:
    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=0.4)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()[:160]
        except asyncio.TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()
        return {"open": True, "latency_ms": latency_ms, "banner": banner}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            "open": False,
            "latency_ms": latency_ms,
            "error": type(exc).__name__,
        }


def _read_local_connections(port: int) -> list[dict]:
    try:
        output = subprocess.check_output(
            ["ss", "-Htan", f"sport = :{port} or dport = :{port}"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    connections: list[dict] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        connections.append(
            {
                "state": parts[0],
                "local": parts[3],
                "peer": parts[4],
            }
        )
    return connections


def _sniff_port_traffic(host: str, port: int, duration: float) -> dict:
    stats = {
        "to_port": 0,
        "from_port": 0,
        "bytes_to": 0,
        "bytes_from": 0,
        "sniffing": False,
    }

    if not can_use_raw_sockets():
        return stats

    try:
        from scapy.all import IP, TCP, sniff
    except ImportError:
        return stats

    stats["sniffing"] = True

    def handle_packet(packet) -> None:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        packet_size = len(packet)

        if ip_layer.dst == host and tcp_layer.dport == port:
            stats["to_port"] += 1
            stats["bytes_to"] += packet_size
        elif ip_layer.src == host and tcp_layer.sport == port:
            stats["from_port"] += 1
            stats["bytes_from"] += packet_size

    try:
        sniff(
            filter=f"tcp and host {host} and port {port}",
            prn=handle_packet,
            store=0,
            timeout=max(1, duration),
        )
    except Exception:
        stats["sniffing"] = False

    return stats


async def stream_port_monitor(
    host: str,
    port: int,
    duration: int = 30,
    interval: float = 2.0,
) -> AsyncIterator[dict]:
    local = get_local_network()
    is_local = local is not None and host == str(local.address)
    sniff_enabled = can_use_raw_sockets()

    yield {
        "type": "start",
        "host": host,
        "port": port,
        "duration": duration,
        "sniff_enabled": sniff_enabled,
        "local_connections": is_local,
    }

    if sniff_enabled:
        message = "Probing the port and watching for TCP traffic on your network segment."
    elif is_local:
        message = "Probing the port and listing local connections on this machine."
    else:
        message = "Probing the port repeatedly. Packet capture is unavailable without raw socket access."

    yield {"type": "status", "message": message}

    sniff_task = asyncio.create_task(
        asyncio.to_thread(_sniff_port_traffic, host, port, float(duration))
    )

    probe_count = 0
    open_count = 0
    latencies: list[float] = []
    end_time = time.time() + duration

    while time.time() < end_time:
        probe = await probe_port(host, port)
        probe_count += 1
        if probe.get("open"):
            open_count += 1
            if probe.get("latency_ms") is not None:
                latencies.append(probe["latency_ms"])

        event = {
            "type": "probe",
            "index": probe_count,
            "timestamp": time.time(),
            **probe,
        }

        if is_local:
            connections = await asyncio.to_thread(_read_local_connections, port)
            if connections:
                event["connections"] = connections

        yield event
        await asyncio.sleep(interval)

    packet_stats = await sniff_task
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None

    yield {
        "type": "summary",
        "probes": probe_count,
        "open_probes": open_count,
        "avg_latency_ms": avg_latency,
        "packets": packet_stats,
    }
    yield {"type": "done"}
