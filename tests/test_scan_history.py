import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.scan_history import _snapshot_host, annotate_scan_changes


class ScanHistoryTests(unittest.TestCase):
    def test_snapshot_preserves_enriched_host_fields(self) -> None:
        host = {
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:01",
            "vendor": "Acme",
            "hostname": "printer.local",
            "connection": "wifi",
            "connection_label": "Wi-Fi",
            "device_role": "Printer",
            "mdns_services": [{"hint": "Printer", "source": "mdns"}],
            "scan_change": "new",
            "scan_change_detail": "ip_changed",
        }
        snapshot = _snapshot_host(host)
        self.assertEqual(snapshot["device_role"], "Printer")
        self.assertEqual(snapshot["connection"], "wifi")
        self.assertNotIn("scan_change", snapshot)
        self.assertNotIn("scan_change_detail", snapshot)

    def test_first_scan_marks_baseline(self) -> None:
        hosts = [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01"}]
        summary = annotate_scan_changes(hosts, None)
        self.assertTrue(summary["first_scan"])
        self.assertIsNone(hosts[0]["scan_change"])

    def test_same_ip_is_seen(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01"}],
        }
        hosts = [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01"}]
        summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 0)
        self.assertEqual(hosts[0]["scan_change"], "seen")

    def test_dhcp_ip_change_matches_by_mac(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01"}],
        }
        hosts = [{"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:01"}]
        summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 0)
        self.assertEqual(hosts[0]["scan_change"], "seen")
        self.assertEqual(hosts[0]["scan_change_detail"], "ip_changed")
        self.assertEqual(summary["disappeared"], [])

    def test_mac_normalization_matches(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [{"ip": "192.168.1.10", "mac": "aa-bb-cc-dd-ee-01"}],
        }
        hosts = [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01"}]
        summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 0)

    def test_hostname_match_when_mac_missing(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [{"ip": "192.168.1.41", "hostname": "SoundTest"}],
        }
        hosts = [{"ip": "192.168.1.99", "hostname": "SoundTest"}]
        summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 0)
        self.assertEqual(summary["disappeared"], [])

    def test_starlink_name_match_when_ip_changes(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [
                {
                    "ip": "192.168.1.50",
                    "mac": "40:F5:20:F8:F4:9D",
                    "starlink_name": "ESP_F8F49D",
                }
            ],
        }
        hosts = [
            {
                "ip": "192.168.1.168",
                "mac": "40:F5:20:F8:F4:9D",
                "starlink_name": "ESP_F8F49D",
            }
        ]
        summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 0)
        self.assertEqual(hosts[0]["scan_change"], "seen")
        self.assertEqual(hosts[0]["scan_change_detail"], "ip_changed")

    def test_mac_match_before_ip_reuse(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:01"}],
        }
        hosts = [
            {"ip": "192.168.1.10", "mac": "BB:BB:CC:DD:EE:02"},
            {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:01"},
        ]
        summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 1)
        self.assertEqual(hosts[0]["scan_change"], "new")
        self.assertEqual(hosts[1]["scan_change"], "seen")

    def test_known_device_not_marked_new(self) -> None:
        last_scan = {
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "hosts": [],
        }
        hosts = [{"ip": "192.168.1.168", "mac": "40:F5:20:F8:F4:9D", "starlink_name": "ESP_F8F49D"}]
        with tempfile.TemporaryDirectory() as tmp:
            known_path = Path(tmp) / "known-devices.json"
            known_path.write_text(
                json.dumps(["mac:40:F5:20:F8:F4:9D", "starlink:esp_f8f49d"]),
                encoding="utf-8",
            )
            with patch("scanner.scan_history.KNOWN_DEVICES_FILE", known_path):
                summary = annotate_scan_changes(hosts, last_scan)
        self.assertEqual(summary["new_count"], 0)
        self.assertEqual(hosts[0]["scan_change"], "seen")
        self.assertEqual(hosts[0]["scan_change_detail"], "known_device")


if __name__ == "__main__":
    unittest.main()
