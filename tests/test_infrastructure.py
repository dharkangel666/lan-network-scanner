import unittest
from unittest.mock import patch

from scanner.infrastructure import (
    _parse_lease_file,
    _read_resolv_conf,
    annotate_host_infrastructure,
    apply_infrastructure_to_hosts,
    build_infrastructure_summary,
    LocalInfraHints,
    ProbeResults,
)


class InfrastructureTests(unittest.TestCase):
    def test_read_resolv_conf(self) -> None:
        sample = "nameserver 192.168.1.1\nnameserver 1.1.1.1\ndomain lan.local\n"
        with patch("scanner.infrastructure.Path") as path_cls:
            path_cls.return_value.exists.return_value = True
            path_cls.return_value.read_text.return_value = sample
            servers, domain = _read_resolv_conf()
        self.assertEqual(servers, ["192.168.1.1", "1.1.1.1"])
        self.assertEqual(domain, "lan.local")

    def test_parse_lease_file_extracts_servers(self) -> None:
        from pathlib import Path
        from tempfile import NamedTemporaryFile

        sample = """
lease {
  option dhcp-server-identifier 192.168.1.1;
  option domain-name-servers 192.168.1.1, 1.1.1.1;
}
"""
        with NamedTemporaryFile("w", delete=False) as handle:
            handle.write(sample)
            path = Path(handle.name)
        try:
            dhcp, dns = _parse_lease_file(path)
        finally:
            path.unlink()
        self.assertEqual(dhcp, "192.168.1.1")
        self.assertEqual(dns, ["192.168.1.1", "1.1.1.1"])

    def test_annotate_gateway_and_dns(self) -> None:
        host = {"ip": "192.168.1.1", "vendor": "Starlink", "ssdp_services": [{"hint": "Router / gateway"}]}
        hints = LocalInfraHints(gateway="192.168.1.1", dns_servers=["192.168.1.1"], dhcp_server="192.168.1.1")
        probes = ProbeResults(dns={"192.168.1.1"})
        roles = annotate_host_infrastructure(host, hints=hints, probes=probes, dhcp_discovered="192.168.1.1")
        role_ids = {role.role for role in roles}
        self.assertIn("gateway", role_ids)
        self.assertIn("dns", role_ids)
        self.assertIn("dhcp", role_ids)
        self.assertIn("router", role_ids)

    def test_build_summary_includes_services(self) -> None:
        hosts = [
            {
                "ip": "192.168.1.1",
                "hostname": "router",
                "infra_roles": [
                    {"role": "gateway", "label": "Gateway", "confidence": "configured"},
                    {"role": "dns", "label": "DNS", "confidence": "configured"},
                ],
            }
        ]
        summary = build_infrastructure_summary(
            hosts,
            hints=LocalInfraHints(gateway="192.168.1.1", dns_servers=["192.168.1.1"]),
            probes=ProbeResults(),
            dhcp_discovered=None,
        )
        self.assertGreaterEqual(summary["service_count"], 2)
        self.assertEqual(summary["services"][0]["role"], "gateway")


    def test_apply_roles_to_host_dict(self) -> None:
        hosts = [{"ip": "192.168.1.1", "vendor": "Router"}]
        apply_infrastructure_to_hosts(
            hosts,
            hints=LocalInfraHints(gateway="192.168.1.1", dns_servers=["192.168.1.1"]),
            probes=ProbeResults(),
            dhcp_discovered=None,
        )
        self.assertEqual(hosts[0]["infra_role_labels"], "Gateway · DNS · Router")


if __name__ == "__main__":
    unittest.main()
