import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scanner.capabilities import get_capabilities_info
from scanner.connection import get_starlink_status
from scanner.infrastructure import identify_infrastructure, read_local_infrastructure_hints
from scanner.discovery import stream_discovery
from scanner.network import get_local_network
from scanner.port_info import get_port_info
from scanner.port_monitor import stream_port_monitor
from scanner.port_profiles import delete_profile, get_profile, list_profiles, save_profile
from scanner.port_results import get_all_host_records, get_recorded_ports, get_recorded_results, get_recorded_udp_results
from scanner.port_scanner import parse_ports, stream_port_scan
from scanner.scan_history import annotate_scan_changes, load_last_scan
from scanner.service_graph import (
    build_host_service_graph,
    build_network_service_graph,
    list_certificates,
    protocol_service_hints,
)
from scanner.service_hints import (
    assemble_host_services,
    filter_discovered_services,
    hints_from_port_spec,
    refresh_host_service_fields,
)
from scanner.ssdp_discovery import browse_ssdp
from scanner.ssh_client import launch_ssh
from scanner.udp_discovery import hints_from_udp_results

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Network Scanner", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class PortScanRequest(BaseModel):
    host: str = Field(..., description="Target IP or hostname")
    ports: str = Field(default="common", description="common, 1-1024, or comma-separated ports")


class PortProfileRequest(BaseModel):
    ports: str = Field(..., min_length=1, description="Port preset or custom list")
    label: str | None = Field(default=None, description="Optional friendly label")


class NotifyRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=120)
    body: str = Field(..., min_length=1, max_length=500)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/infrastructure")
async def infrastructure_info() -> dict:
    last = load_last_scan()
    if last and last.get("summary", {}).get("infrastructure"):
        return last["summary"]["infrastructure"]

    local = get_local_network()
    if local is None:
        raise HTTPException(status_code=500, detail="Could not detect local network")

    hosts = [dict(item) for item in (last or {}).get("hosts", []) if isinstance(item, dict)]
    if not hosts:
        hints = await asyncio.to_thread(read_local_infrastructure_hints)
        return {
            "domain": hints.domain,
            "configured_dns": hints.dns_servers,
            "configured_gateway": hints.gateway,
            "configured_dhcp": hints.dhcp_server,
            "services": [],
            "service_count": 0,
            "message": "Run Scan Network to identify infrastructure on this LAN.",
        }

    return await identify_infrastructure(hosts, local)


@app.get("/api/network")
async def network_info() -> dict:
    local = get_local_network()
    if local is None:
        raise HTTPException(status_code=500, detail="Could not detect local network")

    return {
        "interface": local.interface,
        "address": str(local.address),
        "network": str(local.network),
        "cidr": local.network.prefixlen,
        "starlink": get_starlink_status(),
        **get_capabilities_info(),
    }


@app.get("/api/starlink")
async def starlink_info() -> dict:
    return get_starlink_status()


@app.get("/api/notify/status")
async def notify_status() -> dict:
    return {"available": notify_available()}


@app.post("/api/notify")
async def send_notification(body: NotifyRequest) -> dict:
    return await asyncio.to_thread(send_desktop_notification, body.title, body.body)


@app.get("/api/scan/last")
async def last_scan() -> dict:
    last = load_last_scan()
    if last is None:
        return {"available": False}
    hosts = [dict(host) for host in last.get("hosts", []) if isinstance(host, dict)]
    for host in hosts:
        ip = str(host.get("ip") or "")
        refresh_host_service_fields(
            host,
            scanned_ports=get_recorded_ports(ip),
            port_results=get_recorded_results(ip),
            udp_results=hints_from_udp_results(get_recorded_udp_results(ip)),
            protocol_services=protocol_service_hints(get_recorded_results(ip)),
        )
    summary = annotate_scan_changes(hosts, None)
    saved_summary = last.get("summary") if isinstance(last.get("summary"), dict) else {}
    if saved_summary.get("infrastructure"):
        summary["infrastructure"] = saved_summary["infrastructure"]
    return {
        "available": True,
        "scanned_at": last.get("scanned_at"),
        "network": last.get("network"),
        "hosts": hosts,
        "summary": summary,
        "infrastructure": summary.get("infrastructure"),
    }


@app.get("/api/scan/discovery")
async def discovery_scan() -> StreamingResponse:
    local = get_local_network()
    if local is None:
        raise HTTPException(status_code=500, detail="Could not detect local network")

    async def event_stream():
        yield _sse({"type": "start", "network": str(local.network)})
        async for item in stream_discovery(local):
            if item["event"] == "status":
                yield _sse({"type": "status", "message": item["message"]})
            elif item["event"] == "summary":
                yield _sse({"type": "summary", **{key: value for key, value in item.items() if key != "event"}})
            else:
                yield _sse({"type": "host", "host": item["host"]})
            await asyncio.sleep(0)
        yield _sse({"type": "done"})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/port-profiles")
async def port_profiles() -> dict:
    return {"profiles": list_profiles()}


@app.get("/api/port-profiles/{host}")
async def port_profile(host: str) -> dict:
    profile = get_profile(host)
    if profile is None:
        raise HTTPException(status_code=404, detail="No saved profile for this host")
    return profile


@app.put("/api/port-profiles/{host}")
async def upsert_port_profile(host: str, body: PortProfileRequest) -> dict:
    try:
        parse_ports(body.ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        return save_profile(host, body.ports, body.label)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/hosts/{host}/services")
async def host_services(host: str) -> dict:
    profile = get_profile(host)
    profile_ports: list[int] = []
    if profile and profile.get("ports"):
        try:
            profile_ports = parse_ports(str(profile["ports"]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    last = load_last_scan()
    saved_host = next(
        (item for item in (last or {}).get("hosts", []) if str(item.get("ip")) == host),
        {},
    )

    services, role = assemble_host_services(
        mdns_services=filter_discovered_services(saved_host.get("mdns_services")),
        ssdp_services=saved_host.get("ssdp_services"),
        udp_services=hints_from_udp_results(get_recorded_udp_results(host)),
        scanned_ports=get_recorded_ports(host),
        protocol_services=protocol_service_hints(get_recorded_results(host)),
    )
    return {
        "host": host,
        "services": services,
        "device_role": role,
        "has_profile": bool(profile_ports),
        "profile_ports": profile.get("ports") if profile else None,
    }


@app.get("/api/hosts/{host}/service-graph")
async def host_service_graph(host: str) -> dict:
    last = load_last_scan()
    saved_host = next(
        (item for item in (last or {}).get("hosts", []) if str(item.get("ip")) == host),
        None,
    )
    if saved_host is None:
        saved_host = {"ip": host}
    record = get_all_host_records().get(host, {})
    return build_host_service_graph(
        host,
        mdns_services=filter_discovered_services(saved_host.get("mdns_services")),
        ssdp_services=saved_host.get("ssdp_services"),
        udp_services=hints_from_udp_results(get_recorded_udp_results(host)),
        scanned_ports=record.get("open_ports"),
        port_results=record.get("results"),
    )


@app.get("/api/services/graph")
async def services_graph() -> dict:
    last = load_last_scan()
    if last is None:
        return {"hosts": [], "host_count": 0}
    hosts = [dict(item) for item in last.get("hosts", []) if isinstance(item, dict)]
    return build_network_service_graph(hosts)


@app.get("/api/certificates")
async def certificates() -> dict:
    return {"certificates": list_certificates()}


@app.get("/api/ssdp")
async def ssdp_devices() -> dict:
    devices = await asyncio.to_thread(browse_ssdp)
    flattened = []
    for ip, services in devices.items():
        for service in services:
            flattened.append({**service, "ip": ip})
    return {"devices": flattened, "host_count": len(devices)}


@app.delete("/api/port-profiles/{host}")
async def remove_port_profile(host: str) -> dict:
    if not delete_profile(host):
        raise HTTPException(status_code=404, detail="No saved profile for this host")
    return {"deleted": True, "host": host}


@app.get("/api/ports/{port}")
async def port_info(port: int) -> dict:
    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")
    return get_port_info(port)


@app.get("/api/monitor/port")
async def monitor_port(
    request: Request,
    host: str = Query(..., min_length=1),
    port: int = Query(..., ge=1, le=65535),
    duration: int = Query(default=30, ge=5, le=120),
) -> StreamingResponse:
    async def event_stream():
        async for event in stream_port_monitor(host, port, duration=duration):
            if await request.is_disconnected():
                break
            yield _sse(event)
            await asyncio.sleep(0)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/connect/ssh")
async def connect_ssh(
    host: str = Query(..., min_length=1),
    port: int = Query(default=22, ge=1, le=65535),
    username: str | None = Query(default=None),
) -> dict:
    try:
        return await asyncio.to_thread(launch_ssh, host, port, username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/scan/ports")
async def port_scan(
    host: str = Query(..., min_length=1),
    ports: str = Query(default="common"),
) -> StreamingResponse:
    try:
        port_list = parse_ports(ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not port_list:
        raise HTTPException(status_code=400, detail="No ports to scan")

    async def event_stream():
        yield _sse({"type": "start", "host": host, "total_ports": len(port_list)})
        async for event in stream_port_scan(host, ports=port_list):
            yield _sse(event)
            await asyncio.sleep(0)
        yield _sse({"type": "done"})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/scan/ports")
async def port_scan_post(body: PortScanRequest) -> StreamingResponse:
    return await port_scan(host=body.host, ports=body.ports)


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"
