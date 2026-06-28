import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scanner.capabilities import get_capabilities_info
from scanner.discovery import stream_discovery
from scanner.network import get_local_network
from scanner.port_info import get_port_info
from scanner.port_monitor import stream_port_monitor
from scanner.port_scanner import parse_ports, stream_port_scan
from scanner.ssh_client import launch_ssh

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Network Scanner", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class PortScanRequest(BaseModel):
    host: str = Field(..., description="Target IP or hostname")
    ports: str = Field(default="common", description="common, 1-1024, or comma-separated ports")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


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
        **get_capabilities_info(),
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
            else:
                yield _sse({"type": "host", "host": item["host"]})
            await asyncio.sleep(0)
        yield _sse({"type": "done"})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


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
