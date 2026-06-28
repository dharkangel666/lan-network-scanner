import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.service_hints import hints_from_port_spec, summarize_device_role

CACHE_DIR = Path.home() / ".cache" / "lan-network-scanner"
PROFILES_FILE = CACHE_DIR / "port-profiles.json"


def _normalize_host(host: str) -> str:
    return str(host or "").strip()


def load_profiles() -> dict[str, dict]:
    if not PROFILES_FILE.exists():
        return {}
    try:
        payload = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    profiles = payload.get("profiles")
    return profiles if isinstance(profiles, dict) else {}


def _save_profiles(profiles: dict[str, dict]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": datetime.now(UTC).isoformat(),
        "profiles": profiles,
    }
    PROFILES_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def get_profile(host: str) -> dict | None:
    key = _normalize_host(host)
    if not key:
        return None
    profile = load_profiles().get(key)
    return profile if isinstance(profile, dict) else None


def save_profile(host: str, ports: str, label: str | None = None) -> dict:
    key = _normalize_host(host)
    ports_spec = str(ports or "").strip()
    if not key:
        raise ValueError("Host is required")
    if not ports_spec:
        raise ValueError("Ports specification is required")

    profiles = load_profiles()
    profile = {
        "host": key,
        "ports": ports_spec,
        "label": label.strip() if label else None,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    profiles[key] = profile
    _save_profiles(profiles)
    hints = hints_from_port_spec(ports_spec, source="profile")
    return {
        **profile,
        "service_hints": hints,
        "device_role": summarize_device_role(hints),
    }


def delete_profile(host: str) -> bool:
    key = _normalize_host(host)
    profiles = load_profiles()
    if key not in profiles:
        return False
    del profiles[key]
    _save_profiles(profiles)
    return True


def list_profiles() -> list[dict]:
    return sorted(load_profiles().values(), key=lambda item: item.get("host", ""))
