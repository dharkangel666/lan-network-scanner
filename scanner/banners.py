import asyncio
import re
import ssl


async def read_line_banner(host: str, port: int, timeout: float = 1.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        text = banner.decode("utf-8", errors="ignore").strip()
        return text or None
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def read_ssh_banner(host: str, timeout: float = 1.0) -> str | None:
    return await read_line_banner(host, 22, timeout=timeout)


async def read_http_server_header(host: str, port: int, timeout: float = 1.0) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        headers = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        match = re.search(
            r"^Server:\s*(.+)$",
            headers.decode("utf-8", errors="ignore"),
            re.MULTILINE | re.IGNORECASE,
        )
        return match.group(1).strip() if match else None
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def read_https_server_header(host: str, port: int, timeout: float = 1.0) -> str | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context),
            timeout=timeout,
        )
        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        headers = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        match = re.search(
            r"^Server:\s*(.+)$",
            headers.decode("utf-8", errors="ignore"),
            re.MULTILINE | re.IGNORECASE,
        )
        return match.group(1).strip() if match else None
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
        return None


async def grab_port_banner(host: str, port: int, timeout: float = 0.75) -> str | None:
    if port == 22:
        return await read_ssh_banner(host, timeout=timeout)
    if port in {80, 8080, 8000, 8888, 9000}:
        server = await read_http_server_header(host, port, timeout=timeout)
        return f"Server: {server}" if server else None
    if port in {443, 8443}:
        server = await read_https_server_header(host, port, timeout=timeout)
        return f"Server: {server}" if server else None

    line = await read_line_banner(host, port, timeout=timeout)
    if not line:
        return None

    if port == 21 and line.upper().startswith("220"):
        return line
    if port == 25 and line.upper().startswith("220"):
        return line
    if port == 110 and line.upper().startswith("+OK"):
        return line
    if port == 143 and line.upper().startswith("* OK"):
        return line
    if port == 6379 and line.startswith("$"):
        return "Redis"
    if len(line) > 160:
        return line[:157] + "..."
    return line
