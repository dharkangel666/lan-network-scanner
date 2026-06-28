import unittest

from scanner.mdns_services import _parse_avahi_browse, summarize_device_role
from scanner.port_profiles import delete_profile, get_profile, save_profile


SAMPLE_AVAHI = """
+;enp0s31f6;IPv4;Office PC;_workstation._tcp;local
=;enp0s31f6;IPv4;Office PC;_workstation._tcp;local;office.local;192.168.1.10;9;""
=;enp0s31f6;IPv4;NAS Web;_http._tcp;local;nas.local;192.168.1.20;80;""
=;enp0s31f6;IPv4;NAS SSH;_ssh._tcp;local;nas.local;192.168.1.20;22;""
"""


class SecurityOpsTests(unittest.TestCase):
    def setUp(self) -> None:
        delete_profile("192.168.1.99")

    def tearDown(self) -> None:
        delete_profile("192.168.1.99")

    def test_parse_avahi_services(self) -> None:
        services = _parse_avahi_browse(SAMPLE_AVAHI)
        self.assertIn("192.168.1.10", services)
        self.assertEqual(services["192.168.1.10"][0]["hint"], "Workstation")
        self.assertEqual(len(services["192.168.1.20"]), 2)
        role = summarize_device_role(services["192.168.1.20"])
        self.assertIn("Web", role or "")
        self.assertIn("SSH", role or "")

    def test_save_and_load_port_profile(self) -> None:
        saved = save_profile("192.168.1.99", "22,80,443", label="Server")
        self.assertEqual(saved["ports"], "22,80,443")
        loaded = get_profile("192.168.1.99")
        assert loaded is not None
        self.assertEqual(loaded["label"], "Server")


if __name__ == "__main__":
    unittest.main()
