import unittest

from scanner.service_graph import build_network_service_graph, list_certificates, protocol_service_hints
from scanner.service_hints import assemble_host_services
from scanner.ssdp_discovery import _friendly_hint, _parse_ssdp_response
from scanner.udp_discovery import hints_from_udp_results


class Phase2ServiceTests(unittest.TestCase):
    def test_ssdp_response_parsing(self) -> None:
        payload = (
            "HTTP/1.1 200 OK\r\n"
            "CACHE-CONTROL: max-age=1800\r\n"
            "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            "USN: uuid:device-1::urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
            "SERVER: Linux/4.0 UPnP/1.0\r\n"
            "LOCATION: http://192.168.1.10:49152/description.xml\r\n"
            "\r\n"
        )
        entry = _parse_ssdp_response(payload, "192.168.1.10")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["ip"], "192.168.1.10")
        self.assertEqual(entry["hint"], "Media renderer")

    def test_friendly_hint_mapping(self) -> None:
        self.assertEqual(_friendly_hint("urn:schemas-upnp-org:device:InternetGatewayDevice:1", None), "Router / gateway")

    def test_assemble_includes_ssdp_and_udp(self) -> None:
        services, role = assemble_host_services(
            ssdp_services=[{"hint": "Media renderer", "source": "ssdp", "type": "ssdp:device"}],
            udp_services=hints_from_udp_results(
                [{"port": 53, "service": "DNS", "state": "open", "hint": "DNS"}]
            ),
        )
        self.assertEqual(len(services), 2)
        self.assertIn("Media renderer", role or "")

    def test_protocol_service_hints(self) -> None:
        hints = protocol_service_hints(
            [
                {
                    "port": 443,
                    "probe": {
                        "protocol": "tls",
                        "summary": "router.local",
                        "subject": "router.local",
                    },
                }
            ]
        )
        self.assertEqual(hints[0]["source"], "probe")
        self.assertEqual(hints[0]["hint"], "router.local")

    def test_list_certificates_from_port_results(self) -> None:
        from unittest.mock import patch

        fake_records = {
            "192.168.1.1": {
                "results": [
                    {
                        "port": 443,
                        "certificate": {
                            "protocol": "tls",
                            "subject": "router.local",
                            "issuer": "Let's Encrypt",
                            "not_after": "Jan  1 00:00:00 2030 GMT",
                            "expired": False,
                            "hostname_match": True,
                        },
                    }
                ]
            }
        }
        with patch("scanner.service_graph.get_all_host_records", return_value=fake_records):
            certs = list_certificates()
        self.assertEqual(len(certs), 1)
        self.assertEqual(certs[0]["host"], "192.168.1.1")

    def test_network_graph_uses_udp_from_port_cache(self) -> None:
        from unittest.mock import patch

        hosts = [{"ip": "192.168.1.1", "mdns_services": []}]
        udp_results = [{"port": 53, "service": "DNS", "state": "open", "hint": "DNS"}]
        with (
            patch("scanner.service_graph.get_recorded_udp_results", return_value=udp_results),
            patch("scanner.service_graph.get_all_host_records", return_value={}),
        ):
            graph = build_network_service_graph(hosts)
        apps = graph["hosts"][0]["applications"]
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0]["protocol"], "udp")
        self.assertEqual(apps[0]["port"], 53)


if __name__ == "__main__":
    unittest.main()
