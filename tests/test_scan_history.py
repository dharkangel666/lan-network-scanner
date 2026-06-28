import unittest

from scanner.scan_history import annotate_scan_changes


class ScanHistoryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
