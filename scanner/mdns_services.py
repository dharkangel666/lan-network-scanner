import subprocess
from collections import defaultdict

SERVICE_HINTS: dict[str, str] = {
    "_ssh._tcp": "SSH",
    "_sftp-ssh._tcp": "SFTP",
    "_http._tcp": "Web",
    "_https._tcp": "HTTPS",
    "_smb._tcp": "File sharing",
    "_afpovertcp._tcp": "Apple file sharing",
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "AirPlay audio",
    "_googlecast._tcp": "Chromecast",
    "_hap._tcp": "HomeKit",
    "_printer._tcp": "Printer",
    "_ipp._tcp": "Printer",
    "_scanner._tcp": "Scanner",
    "_spotify-connect._tcp": "Spotify",
    "_sonos._tcp": "Sonos",
    "_raspberrypi._tcp": "Raspberry Pi",
    "_workstation._tcp": "Workstation",
    "_device-info._tcp": "Device info",
    "_nut._tcp": "UPS",
    "_plexmediaserver._tcp": "Plex",
    "_home-assistant._tcp": "Home Assistant",
    "_mqtt._tcp": "MQTT",
    "_adb._tcp": "Android debug",
}


def _friendly_service_type(service_type: str) -> str:
    base = service_type.split(".")[0].strip("_").replace("-", " ")
    return base.title() if base else service_type


def service_hint(service_type: str) -> str:
    return SERVICE_HINTS.get(service_type, _friendly_service_type(service_type))


def _parse_avahi_browse(stdout: str) -> dict[str, list[dict]]:
    by_ip: dict[str, dict[str, dict]] = defaultdict(dict)

    for line in stdout.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 9:
            continue
        name = parts[3].strip()
        service_type = parts[4].strip()
        address = parts[7].strip()
        if not address or address in {"0.0.0.0", "127.0.0.1"}:
            continue

        entry = {
            "type": service_type,
            "name": name,
            "hint": service_hint(service_type),
        }
        key = f"{service_type}|{name}"
        by_ip[address][key] = entry

    return {ip: list(entries.values()) for ip, entries in by_ip.items()}


def browse_mdns_services(timeout: float = 5.0) -> dict[str, list[dict]]:
    try:
        completed = subprocess.run(
            ["avahi-browse", "-a", "-r", "-t", "-p"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    if completed.returncode != 0 and not completed.stdout:
        return {}

    return _parse_avahi_browse(completed.stdout)


def summarize_device_role(services: list[dict], limit: int = 4) -> str | None:
    if not services:
        return None
    hints: list[str] = []
    seen: set[str] = set()
    for service in services:
        hint = service.get("hint")
        if not hint or hint in seen:
            continue
        seen.add(hint)
        hints.append(hint)
        if len(hints) >= limit:
            break
    return " · ".join(hints) if hints else None


def resolve_services_for_ip(ip: str, services_by_ip: dict[str, list[dict]]) -> list[dict]:
    return list(services_by_ip.get(ip, []))
