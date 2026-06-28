import asyncio
from collections.abc import AsyncIterator, Callable, Iterable

from scanner.banners import grab_port_banner
from scanner.port_info import get_port_info
from scanner.port_results import record_port_scan

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000,
]
ALL_PORTS = list(range(1, 65536))
BATCH_SIZE = 500


def parse_ports(spec: str | None) -> list[int]:
    if not spec or spec.strip().lower() in {"common", "default"}:
        return COMMON_PORTS.copy()

    normalized = spec.strip().lower()
    if normalized in {"all", "full", "1-65535"}:
        return ALL_PORTS.copy()

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if part.lower() in {"all", "full"}:
            ports.update(ALL_PORTS)
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError("Port range must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError("Port must be between 1 and 65535")
            ports.add(port)

    return sorted(ports)


def _scan_settings(port_count: int, concurrency: int, timeout: float) -> tuple[int, float]:
    if port_count > 10000:
        return max(concurrency, 250), min(timeout, 0.15)
    if port_count > 1000:
        return max(concurrency, 150), min(timeout, 0.25)
    return concurrency, timeout


async def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def scan_ports(
    host: str,
    ports: Iterable[int] | None = None,
    concurrency: int = 100,
    timeout: float = 0.5,
    on_port: Callable[[dict], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[dict]:
    target_ports = list(ports or COMMON_PORTS)
    concurrency, timeout = _scan_settings(len(target_ports), concurrency, timeout)
    semaphore = asyncio.Semaphore(concurrency)
    open_ports: list[dict] = []

    async def check_port(port: int) -> None:
        async with semaphore:
            if await scan_port(host, port, timeout=timeout):
                info = get_port_info(port)
                banner = await grab_port_banner(host, port, timeout=min(timeout + 0.35, 0.9))
                result = {
                    "port": port,
                    "service": info["service"],
                    "state": "open",
                    "description": info["description"],
                    "common_use": info["common_use"],
                    "risk": info["risk"],
                    "banner": banner,
                }
                open_ports.append(result)
                if on_port:
                    on_port(result)

    total = len(target_ports)
    for offset in range(0, total, BATCH_SIZE):
        batch = target_ports[offset : offset + BATCH_SIZE]
        await asyncio.gather(*(check_port(port) for port in batch))
        if on_progress:
            on_progress(min(offset + len(batch), total), total)

    open_ports.sort(key=lambda item: item["port"])
    record_port_scan(host, [item["port"] for item in open_ports], open_ports)
    return open_ports


async def stream_port_scan(
    host: str,
    ports: Iterable[int] | None = None,
    concurrency: int = 100,
    timeout: float = 0.5,
) -> AsyncIterator[dict]:
    queue: asyncio.Queue[dict | None] = asyncio.Queue()

    def on_port(result: dict) -> None:
        queue.put_nowait({"type": "port", "result": result})

    def on_progress(scanned: int, total: int) -> None:
        queue.put_nowait({"type": "progress", "scanned": scanned, "total": total})

    async def run_scan() -> None:
        try:
            await scan_ports(
                host,
                ports=ports,
                concurrency=concurrency,
                timeout=timeout,
                on_port=on_port,
                on_progress=on_progress,
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
