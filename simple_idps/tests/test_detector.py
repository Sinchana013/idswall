"""
test_detector.py - Unit Tests for Detection Engine

Verifies all detection logic, boundary conditions, sliding window expiration,
cooldown suppression, and input validation without external dependencies.
"""

import sys
import unittest
from pathlib import Path

# Add simple_idps directory to path
parent_dir = Path(__file__).resolve().parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from detector import Detector


class TestDetector(unittest.TestCase):
    """Test suite for Detector class."""

    def setUp(self) -> None:
        """Create a fresh Detector instance before each test."""
        self.detector = Detector()

    def test_normal_traffic_no_alerts(self) -> None:
        """Normal web traffic to a few standard ports must not trigger any alerts."""
        alerts = []
        for port in [80, 443, 80, 53, 443, 80]:
            alerts.extend(
                self.detector.feed(src_ip="192.168.1.50", dst_port=port, timestamp=100.0)
            )
        self.assertEqual(len(alerts), 0)

    def test_port_scan_exact_threshold_boundary(self) -> None:
        """
        Threshold boundary test:
        - Exactly 20 distinct ports within 10 seconds must NOT trigger an alert.
        - The 21st distinct port within 10 seconds MUST trigger an alert.
        """
        src = "192.168.1.100"

        # Feed exactly 20 distinct ports
        alerts_20 = []
        for p in range(1, 21):  # ports 1 to 20
            alerts_20.extend(
                self.detector.feed(src_ip=src, dst_port=p, timestamp=100.0 + (p * 0.1))
            )

        self.assertEqual(
            len(alerts_20),
            0,
            "Exactly 20 distinct ports should NOT trigger PORT_SCAN (> 20 required)",
        )

        # Feed the 21st distinct port
        alerts_21 = self.detector.feed(src_ip=src, dst_port=21, timestamp=102.5)
        self.assertEqual(
            len(alerts_21),
            1,
            "The 21st distinct port MUST trigger a PORT_SCAN alert",
        )
        self.assertEqual(alerts_21[0]["type"], "PORT_SCAN")
        self.assertEqual(alerts_21[0]["severity"], "HIGH")
        self.assertEqual(alerts_21[0]["src_ip"], src)

    def test_repeated_traffic_same_port_does_not_inflate_count(self) -> None:
        """
        Multiple packets to the same port must count as only 1 distinct port,
        not triggering a port scan alert.
        """
        src = "192.168.1.101"
        alerts = []
        for _ in range(50):
            alerts.extend(
                self.detector.feed(src_ip=src, dst_port=443, timestamp=100.0)
            )
        self.assertEqual(len(alerts), 0)

    def test_port_scan_window_expiration(self) -> None:
        """
        Packets outside the 10-second sliding window must expire and not contribute
        to the distinct port count.
        """
        src = "192.168.1.102"

        # Send 15 distinct ports at t = 100.0
        for p in range(1, 16):
            self.detector.feed(src_ip=src, dst_port=p, timestamp=100.0)

        # Fast forward 15 seconds (outside the 10-second window: t = 115.0)
        # Send 10 different distinct ports at t = 115.0
        alerts = []
        for p in range(16, 26):
            alerts.extend(
                self.detector.feed(src_ip=src, dst_port=p, timestamp=115.0)
            )

        # The earlier 15 ports expired, so only 10 distinct ports are currently in window.
        self.assertEqual(
            len(alerts),
            0,
            "Expired ports outside the 10s window must not trigger PORT_SCAN",
        )

    def test_traffic_burst_exact_threshold_boundary(self) -> None:
        """
        Threshold boundary test for traffic burst:
        - Exactly 300 packets in 5 seconds must NOT trigger an alert.
        - The 301st packet MUST trigger a TRAFFIC_BURST alert.
        """
        src = "192.168.1.200"

        # Exactly 300 packets within 2 seconds
        alerts_300 = []
        for i in range(300):
            alerts_300.extend(
                self.detector.feed(src_ip=src, dst_port=80, timestamp=200.0 + (i * 0.005))
            )
        self.assertEqual(
            len(alerts_300),
            0,
            "Exactly 300 packets should NOT trigger TRAFFIC_BURST (> 300 required)",
        )

        # The 301st packet at t = 201.6
        alerts_301 = self.detector.feed(src_ip=src, dst_port=80, timestamp=201.6)
        self.assertEqual(
            len(alerts_301),
            1,
            "The 301st packet within 5s MUST trigger a TRAFFIC_BURST alert",
        )
        self.assertEqual(alerts_301[0]["type"], "TRAFFIC_BURST")
        self.assertEqual(alerts_301[0]["severity"], "MEDIUM")
        self.assertEqual(alerts_301[0]["src_ip"], src)

    def test_alert_cooldown_suppression(self) -> None:
        """
        Consecutive threshold crossings within the cooldown window must NOT
        generate uncontrolled duplicate alerts.
        """
        src = "192.168.1.150"

        # Trigger port scan alert on 21st port
        first_alert = None
        for p in range(1, 22):
            res = self.detector.feed(src_ip=src, dst_port=p, timestamp=100.0 + (p * 0.1))
            if res:
                first_alert = res

        self.assertIsNotNone(first_alert)

        # Now send 10 more distinct ports within cooldown (default cooldown = 10s)
        suppressed_alerts = []
        for p in range(22, 32):
            res = self.detector.feed(src_ip=src, dst_port=p, timestamp=103.0 + (p * 0.1))
            suppressed_alerts.extend(res)

        self.assertEqual(
            len(suppressed_alerts),
            0,
            "Alerts within the cooldown window must be suppressed to avoid alert spam",
        )

    def test_arp_initial_mapping_records_without_alert(self) -> None:
        """First observation of an IP-to-MAC mapping must be recorded without alerting."""
        alerts = self.detector.feed(
            arp_ip="192.168.1.1",
            arp_mac="00:11:22:33:44:55",
            timestamp=100.0,
        )
        self.assertEqual(len(alerts), 0)

        # Repeated observation of the same mapping must also not alert
        alerts2 = self.detector.feed(
            arp_ip="192.168.1.1",
            arp_mac="00:11:22:33:44:55",
            timestamp=105.0,
        )
        self.assertEqual(len(alerts2), 0)

    def test_arp_changed_mac_triggers_anomaly(self) -> None:
        """A changed MAC address for a known IP must trigger an ARP_ANOMALY alert."""
        # Initial mapping
        self.detector.feed(
            arp_ip="192.168.1.1",
            arp_mac="00:11:22:33:44:55",
            timestamp=100.0,
        )

        # MAC change / conflict
        alerts = self.detector.feed(
            arp_ip="192.168.1.1",
            arp_mac="de:ad:be:ef:00:01",
            timestamp=102.0,
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "ARP_ANOMALY")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["src_ip"], "192.168.1.1")
        self.assertIn("00:11:22:33:44:55", alerts[0]["message"])
        self.assertIn("de:ad:be:ef:00:01", alerts[0]["message"])

    def test_invalid_and_missing_inputs_do_not_crash(self) -> None:
        """Invalid IPs, missing fields, or out-of-range ports must be handled gracefully."""
        # None inputs
        self.assertEqual(self.detector.feed(), [])

        # Invalid IP strings
        self.assertEqual(self.detector.feed(src_ip="not_an_ip", dst_port=80), [])
        self.assertEqual(self.detector.feed(src_ip="999.999.999.999", dst_port=80), [])
        self.assertEqual(self.detector.feed(src_ip="", dst_port=80), [])

        # Negative port or out-of-range port
        self.assertEqual(self.detector.feed(src_ip="1.2.3.4", dst_port=-1), [])
        self.assertEqual(self.detector.feed(src_ip="1.2.3.4", dst_port=70000), [])
        self.assertEqual(self.detector.feed(src_ip="1.2.3.4", dst_port="eighty"), [])  # type: ignore

        # Invalid ARP inputs
        self.assertEqual(self.detector.feed(arp_ip="bad_ip", arp_mac="00:11:22"), [])
        self.assertEqual(self.detector.feed(arp_ip="1.2.3.4", arp_mac=None), [])
        self.assertEqual(self.detector.feed(arp_ip=None, arp_mac="00:11:22:33:44:55"), [])

    def test_per_source_isolation(self) -> None:
        """Events from one source must never contaminate another source's counts."""
        src_a = "10.0.0.1"
        src_b = "10.0.0.2"

        # Source A hits 15 distinct ports
        for p in range(1, 16):
            self.detector.feed(src_ip=src_a, dst_port=p, timestamp=100.0)

        # Source B hits 15 different distinct ports
        for p in range(16, 31):
            self.detector.feed(src_ip=src_b, dst_port=p, timestamp=100.0)

        # Neither has exceeded 20 distinct ports
        self.assertEqual(len(self.detector._port_history[src_a]), 15)
        self.assertEqual(len(self.detector._port_history[src_b]), 15)


if __name__ == "__main__":
    unittest.main()
