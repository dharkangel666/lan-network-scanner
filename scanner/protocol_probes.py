"""Lightweight application-layer probes for open TCP services."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 9000}
TLS_PORTS = {443, 8443, 993, 995, 636, 465}


def _cert_expired(not_after: str) -> bool:
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return expiry < datetime.now(UTC)
    except ValueError:
        return False


def _hostname_matches_cert(host: str, subject: dict[str, str], san: list[str]) -> bool | None:
    names = {name.lower() for name in san if name}
    common = str(subject.get("commonName") or "").lower()
    if common:
        names.add(common)
    if not names:
        return None
    host_lower = host.lower()
    for name in names:
        if name == host_lower:
            return True
        if name.startswith("*.") and host_lower.endswith(name[1:]):
            return True
    return False


def _parse_x509_names(cert: dict[str, Any]) -> tuple[dict[str, str], dict[str, str], list[str]]:
    subject = {key: value for key, value in (cert.get("subject") or ())}
    issuer = {key: value for key, value in (cert.get("issuer") or ())}
    san = [value for kind, value in (cert.get("subjectAltName") or ()) if kind == "DNS"]
    return subject, issuer, san


def format_certificate_probe(probe: dict[str, Any]) -> str | None:
    parts: list[str] = []
    if probe.get("subject"):
        parts.append(str(probe["subject"]))
    if probe.get("issuer"):
        parts.append(f"issuer {probe['issuer']}")
    if probe.get("not_after"):
        parts.append(f"until {probe['not_after']}")
    return " · ".join(parts) if parts else None


async def probe_http(host: str, port: int, timeout: float = 1.0) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "http", "port": port}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.write(
            f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(),
        )
        await writer.drain()
        payload = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        text = payload.decode("utf-8", errors="ignore")
        server = re.search(r"^Server:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
        title = re.search(r"<title[^>]*>([^<]+)</title>", text, re.IGNORECASE)
        if server:
            result["server"] = server.group(1).strip()[:160]
        if title:
            result["title"] = title.group(1).strip()[:160]
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    return result


async def probe_tls(host: str, port: int, timeout: float = 1.0) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "tls", "port": port}

    def fetch_cert() -> dict[str, Any] | None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert()

    try:
        cert = await asyncio.wait_for(asyncio.to_thread(fetch_cert), timeout=timeout + 0.5)
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return result

    if not cert:
        return result

    subject, issuer, san = _parse_x509_names(cert)
    result["subject"] = subject.get("commonName") or ""
    result["issuer"] = issuer.get("organizationName") or issuer.get("commonName") or ""
    not_after = cert.get("notAfter")
    if not_after:
        result["not_after"] = not_after
        result["expired"] = _cert_expired(not_after)
    if san:
        result["san"] = san[:12]
    match = _hostname_matches_cert(host, subject, san)
    if match is not None:
        result["hostname_match"] = match
    return result


async def probe_ssh(host: str, port: int = 22, timeout: float = 1.0) -> dict[str, Any]:
    result: dict[str, Any] = {"protocol": "ssh", "port": port}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        text = banner.decode("utf-8", errors="ignore").strip()
        if text:
            result["banner"] = text[:200]
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        pass
    return result


async def probe_open_port(host: str, port: int, service: str | None = None, timeout: float = 0.9) -> dict[str, Any]:
    service_name = (service or "").lower()
    probes: list[dict[str, Any]] = []

    if port == 22 or "ssh" in service_name:
        ssh = await probe_ssh(host, port, timeout=timeout)
        if ssh.get("banner"):
            probes.append(ssh)

    if port in HTTP_PORTS or "http" in service_name:
        http = await probe_http(host, port, timeout=timeout)
        if http.get("server") or http.get("title"):
            probes.append(http)

    if port in TLS_PORTS or "https" in service_name or port in {443, 8443}:
        tls = await probe_tls(host, port, timeout=timeout)
        if tls.get("subject") or tls.get("issuer"):
            probes.append(tls)
        if port not in HTTP_PORTS and "http" not in service_name:
            pass
        elif not any(item.get("protocol") == "http" for item in probes):
            https_http = await probe_http(host, port, timeout=timeout)
            if https_http.get("server") or https_http.get("title"):
                probes.append(https_http)

    if not probes:
        return {}

    primary = probes[0]
    summary_parts: list[str] = []
    for probe in probes:
        if probe.get("title"):
            summary_parts.append(str(probe["title"]))
        elif probe.get("server"):
            summary_parts.append(f"Server {probe['server']}")
        elif probe.get("banner"):
            summary_parts.append(str(probe["banner"]))
        elif probe.get("subject"):
            summary_parts.append(str(probe["subject"]))
    if summary_parts:
        primary = {**primary, "summary": " · ".join(summary_parts)[:200]}
    primary["probes"] = probes
    return primary
