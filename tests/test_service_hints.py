import unittest

from scanner.service_hints import assemble_host_services, hints_from_port_spec, summarize_device_role


class ServiceHintsTests(unittest.TestCase):
    def test_profile_only_role(self) -> None:
        services, role = assemble_host_services(profile_ports=[22, 80, 443])
        self.assertEqual(len(services), 3)
        self.assertIn("saved profile", role or "")

    def test_scan_overrides_profile_duplicate(self) -> None:
        services, role = assemble_host_services(
            scanned_ports=[22],
            profile_ports=[22, 80],
        )
        self.assertEqual(len(services), 2)
        self.assertIn("SSH", role or "")

    def test_hints_from_port_spec(self) -> None:
        hints = hints_from_port_spec("22,8080", source="profile")
        self.assertEqual(hints[0]["hint"], "SSH")
        self.assertEqual(summarize_device_role(hints), "SSH · HTTP (saved profile)")


if __name__ == "__main__":
    unittest.main()
