import unittest

from scanner.service_hints import (
    assemble_host_services,
    filter_discovered_services,
    hints_from_port_spec,
    summarize_device_role,
)


class ServiceHintsTests(unittest.TestCase):
    def test_profile_ports_not_listed_as_services(self) -> None:
        services, role = assemble_host_services(scanned_ports=[8443, 9000])
        self.assertEqual(len(services), 2)
        self.assertIn("HTTPS", role or "")
        self.assertIn("HTTP", role or "")

    def test_filter_strips_saved_profile_hints(self) -> None:
        stored = [
            {"hint": "SSH", "source": "profile"},
            {"hint": "HTTPS", "source": "scan"},
        ]
        filtered = filter_discovered_services(stored)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["hint"], "HTTPS")

    def test_scan_overrides_duplicate_hint(self) -> None:
        services, role = assemble_host_services(
            scanned_ports=[22],
            mdns_services=[{"hint": "SSH", "source": "mdns", "type": "_ssh._tcp"}],
        )
        self.assertEqual(len(services), 1)
        self.assertIn("SSH", role or "")

    def test_hints_from_port_spec(self) -> None:
        hints = hints_from_port_spec("22,8080", source="profile")
        self.assertEqual(hints[0]["hint"], "SSH")
        self.assertEqual(summarize_device_role(hints), "SSH · HTTP (saved profile)")


if __name__ == "__main__":
    unittest.main()
