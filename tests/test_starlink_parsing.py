import json
import unittest

from scanner.connection import _parse_starlink_response, summarize_starlink_clients, StarlinkClientMap


SAMPLE_RESPONSE = """
{
  "wifiGetClients": {
    "clients": [
      {
        "name": "Controller",
        "macAddress": "74:24:9f:4c:87:d0",
        "iface": "ETH",
        "role": "CONTROLLER"
      },
      {
        "name": "Phone",
        "macAddress": "aa:bb:cc:dd:ee:01",
        "ipAddress": "192.168.1.50",
        "signalStrength": -55,
        "snr": 40,
        "channelWidth": 20,
        "iface": "RF_5GHZ",
        "role": "CLIENT",
        "rxStats": {"rateMbps": 866}
      }
    ]
  }
}
"""


class StarlinkParsingTests(unittest.TestCase):
    def test_parse_clients_and_summary(self) -> None:
        by_mac, by_ip, records = _parse_starlink_response(SAMPLE_RESPONSE)
        self.assertEqual(len(records), 2)
        self.assertIn("192.168.1.50", by_ip)
        phone = by_ip["192.168.1.50"]
        self.assertEqual(phone.name, "Phone")
        self.assertEqual(phone.signal_dbm, -55)
        self.assertEqual(phone.snr, 40)
        self.assertEqual(phone.connection.detail, "5 GHz")
        self.assertEqual(phone.link_rate_mbps, 866.0)

        client_map = StarlinkClientMap(
            by_mac=by_mac,
            by_ip=by_ip,
            records=records,
            router_host="192.168.1.1",
            client_count=len(records),
        )
        summary = summarize_starlink_clients(client_map, matched_count=1, scanned_count=2)
        self.assertEqual(summary["client_count"], 1)
        self.assertEqual(summary["wifi_clients"], 1)
        self.assertEqual(summary["wifi_5ghz"], 1)
        self.assertEqual(summary["avg_snr"], 40.0)


if __name__ == "__main__":
    unittest.main()
