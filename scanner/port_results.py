import json
from datetime import UTC, datetime
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "lan-network-scanner"
PORT_RESULTS_FILE = CACHE_DIR / "port-results.json"


def _normalize_host(host: str) -> str:
    return str(host or "").strip()


def load_results() -> dict[str, dict]:
    if not PORT_RESULTS_FILE.exists():
        return {}
    try:
        payload = json.loads(PORT_RESULTS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    hosts = payload.get("hosts")
    return hosts if isinstance(hosts, dict) else {}


def _save_results(hosts: dict[str, dict]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now(UTC).isoformat(),
        "hosts": hosts,
    }
    PORT_RESULTS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def record_port_scan(host: str, open_ports: list[int], results: list[dict] | None = None) -> None:
    key = _normalize_host(host)
    if not key:
        return

    hosts = load_results()
    hosts[key] = {
        "host": key,
        "open_ports": sorted({int(port) for port in open_ports}),
        "results": results or [],
        "scanned_at": datetime.now(UTC).isoformat(),
    }
    _save_results(hosts)


def get_recorded_ports(host: str) -> list[int]:
    key = _normalize_host(host)
    record = load_results().get(key)
    if not record:
        return []
    ports = record.get("open_ports")
    if not isinstance(ports, list):
        return []
    return [int(port) for port in ports]
