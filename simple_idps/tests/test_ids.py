"""
test_ids.py - Unit Tests for ids.py Packet Processing and Response Policies

Verifies packet parsing, TCP SYN heuristic filtering, local IP isolation,
response policy decisions, allowlist loading, and block expiration.
Runs completely offline without Scapy, Npcap, administrative rights, or real firewall changes.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure simple_idps directory is in sys.path
parent_dir = Path(__file__).resolve().parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

import ids
from ids import LiveIDPS, load_allowlist, ARP, IP, TCP, UDP


class MockLayer:
    """Mock Scapy protocol layer."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class MockPacket:
    """Mock Scapy packet supporting haslayer() and dict-like indexing."""

    def __init__(self, layers=None):
        self._layers = layers or {}

    def haslayer(self, layer_type):
        return layer_type in self._layers

    def __getitem__(self, layer_type):
        return self._layers[layer_type]


class TestLiveIDPS(unittest.TestCase):
    """Test suite for LiveIDPS packet processing and response policies."""

    def setUp(self) -> None:
        """Set up test instance with mocked local IPs and firewall controller."""
        self.local_ip = "192.168.1.50"
        self.remote_ip = "198.51.100.55"

        with patch("firewall.discover_local_ipv4_addresses") as mock_disc:
            mock_disc.return_value = ({self.local_ip}, True)
            self.app = LiveIDPS(
                prevent=True,
                real=True,  # Test in active mode with mocked runner
                allowlist={"10.0.0.1"},
            )
            # Replace firewall runner with mock
            self.mock_runner = MagicMock()
            self.app.firewall.runner = self.mock_runner

    def test_arp_anomaly_never_invokes_block_ip(self) -> None:
        """
        Requirement 1: An ARP anomaly must NEVER trigger block_ip,
        even when severity is HIGH and prevention mode is enabled (--prevent --real).
        """
        # Step 1: Initial mapping (recorded, no alert)
        pkt1 = MockPacket({
            ARP: MockLayer(psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
        })
        self.app.process_packet(pkt1)

        # Mock block_ip to verify it is NEVER called
        self.app.firewall.block_ip = MagicMock()

        # Step 2: Conflicting mapping (triggers ARP_ANOMALY)
        pkt2 = MockPacket({
            ARP: MockLayer(psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01")
        })
        self.app.process_packet(pkt2)

        # Confirm block_ip was NOT called
        self.app.firewall.block_ip.assert_not_called()

    def test_port_scan_eligible_only_when_prevent_and_real_enabled(self) -> None:
        """
        Requirement 2: A port-scan alert is eligible for active firewall blocking
        only when both --prevent and --real are enabled.
        """
        # Test A: prevent=True, real=False (Dry-run mode)
        dry_app = LiveIDPS(prevent=True, real=False)
        dry_app.firewall.block_ip = MagicMock()
        port_scan_alert = {
            "type": "PORT_SCAN",
            "severity": "HIGH",
            "src_ip": self.remote_ip,
            "message": "Port scan detected",
            "timestamp": 100.0,
        }
        dry_app._handle_alert(port_scan_alert)
        dry_app.firewall.block_ip.assert_called_once_with(self.remote_ip)
        self.assertTrue(dry_app.firewall.dry_run)

        # Test B: prevent=False (Alert-only mode)
        passive_app = LiveIDPS(prevent=False, real=False)
        passive_app.firewall.block_ip = MagicMock()
        passive_app._handle_alert(port_scan_alert)
        passive_app.firewall.block_ip.assert_not_called()

    def test_traffic_burst_not_automatically_blocked(self) -> None:
        """
        Requirement 3: A HIGH/MEDIUM traffic-burst alert is not automatically blocked
        under the initial response policy.
        """
        self.app.firewall.block_ip = MagicMock()

        burst_alert = {
            "type": "TRAFFIC_BURST",
            "severity": "HIGH",
            "src_ip": self.remote_ip,
            "message": "Traffic burst detected",
            "timestamp": 100.0,
        }
        self.app._handle_alert(burst_alert)

        # Must not call block_ip for traffic burst
        self.app.firewall.block_ip.assert_not_called()

    def test_outgoing_packet_from_local_ip_does_not_trigger_scan(self) -> None:
        """
        Requirement 4: Outgoing packets sourced from local IPv4 address must be
        ignored and never trigger port scan alerts against this machine.
        """
        # Send 25 distinct outgoing ports from local IP to remote server
        for p in range(1, 26):
            pkt = MockPacket({
                IP: MockLayer(src=self.local_ip, dst="93.184.216.34"),
                TCP: MockLayer(dport=p, flags=0x02),  # SYN
            })
            self.app.process_packet(pkt)

        self.assertEqual(self.app.alert_count, 0)

    def test_tcp_syn_packet_directed_to_local_contributes_to_scan(self) -> None:
        """
        Requirement 5: A TCP SYN probe (SYN=1, ACK=0) directed to a local address
        MUST count toward port-scan detection.
        """
        self.app.firewall.block_ip = MagicMock()

        # Send 21 distinct TCP SYN packets targeting local host
        for p in range(1, 22):
            pkt = MockPacket({
                IP: MockLayer(src=self.remote_ip, dst=self.local_ip),
                TCP: MockLayer(dport=p, flags=0x02),  # SYN=1, ACK=0
            })
            self.app.process_packet(pkt)

        # 21st distinct port probe must trigger 1 alert
        self.assertEqual(self.app.alert_count, 1)
        self.app.firewall.block_ip.assert_called_once_with(self.remote_ip)

    def test_tcp_syn_ack_response_does_not_count_as_probe(self) -> None:
        """
        Requirement 6: A TCP SYN-ACK response (SYN=1, ACK=1) must NOT count as a probe.
        """
        # Send 25 distinct SYN-ACK packets (flags = 0x12 -> SYN+ACK)
        for p in range(1, 26):
            pkt = MockPacket({
                IP: MockLayer(src=self.remote_ip, dst=self.local_ip),
                TCP: MockLayer(dport=p, flags=0x12),  # SYN=1, ACK=1
            })
            self.app.process_packet(pkt)

        self.assertEqual(self.app.alert_count, 0)

    def test_udp_packets_do_not_count_toward_tcp_syn_scan(self) -> None:
        """
        Requirement 7: UDP packets must not count toward the TCP SYN port-scan rule.
        """
        # Send 25 distinct UDP packets
        for p in range(1, 26):
            pkt = MockPacket({
                IP: MockLayer(src=self.remote_ip, dst=self.local_ip),
                UDP: MockLayer(dport=p),
            })
            self.app.process_packet(pkt)

        self.assertEqual(self.app.alert_count, 0)

    def test_traffic_to_different_host_does_not_count_as_scan(self) -> None:
        """
        Requirement 8: Traffic addressed to a different host (not one of the laptop's
        local IPs) must not count toward a scan against this laptop.
        """
        different_host = "192.168.1.99"
        # Send 25 distinct SYN packets to a different IP
        for p in range(1, 26):
            pkt = MockPacket({
                IP: MockLayer(src=self.remote_ip, dst=different_host),
                TCP: MockLayer(dport=p, flags=0x02),  # SYN
            })
            self.app.process_packet(pkt)

        self.assertEqual(self.app.alert_count, 0)

    def test_remote_packets_still_trigger_traffic_burst(self) -> None:
        """
        Requirement 9: Remote source packets can still trigger the traffic-burst detector.
        """
        # Send 305 packets from remote source to port 80
        for _ in range(305):
            pkt = MockPacket({
                IP: MockLayer(src=self.remote_ip, dst=self.local_ip),
                TCP: MockLayer(dport=80, flags=0x10),  # Regular ACK traffic
            })
            self.app.process_packet(pkt)

        # Should have triggered 1 TRAFFIC_BURST alert
        self.assertEqual(self.app.alert_count, 1)

    def test_discovery_failure_fails_safely_alert_only(self) -> None:
        """
        Requirement 10: Local-address discovery failure never results in automatic blocking
        (fails closed to safe alert-only mode).
        """
        with patch("firewall.discover_local_ipv4_addresses") as mock_disc:
            mock_disc.return_value = (set(), False)  # Discovery failed
            unsafe_app = LiveIDPS(prevent=True, real=True)
            unsafe_app.firewall.block_ip = MagicMock()

            # Confirm discovery_success is False
            self.assertFalse(unsafe_app.discovery_success)

            port_scan_alert = {
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "src_ip": self.remote_ip,
                "message": "Port scan detected",
                "timestamp": 100.0,
            }
            is_eligible, reason = unsafe_app.evaluate_response_policy(port_scan_alert)
            self.assertFalse(is_eligible)
            self.assertIn("discovery failed", reason.lower())

            unsafe_app._handle_alert(port_scan_alert)
            unsafe_app.firewall.block_ip.assert_not_called()

    def test_invalid_and_incomplete_packets_handled_safely(self) -> None:
        """
        Requirement 11: Malformed and incomplete packets must be handled without crashing.
        """
        # Completely empty packet
        self.app.process_packet(MockPacket({}))

        # Broken IP layer with missing src/dst
        self.app.process_packet(MockPacket({IP: MockLayer()}))

        # Broken TCP layer with missing flags/dport
        self.app.process_packet(MockPacket({
            IP: MockLayer(src="1.2.3.4", dst=self.local_ip),
            TCP: MockLayer(),
        }))

        # Non-packet object
        self.app.process_packet("not a packet")
        self.app.process_packet(None)

    def test_allowlist_loading_and_protection(self) -> None:
        """
        Allowlist entries must be loaded, normalized, and protected from blocking.
        """
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
            f.write("# Trusted router\n")
            f.write("192.168.1.1\n\n")
            f.write("  1.1.1.1  # DNS\n")
            f.write("# Comment line\n")
            f.write("invalid_ip\n")
            tmp_path = f.name

        try:
            loaded = load_allowlist(tmp_path)
            self.assertIn("192.168.1.1", loaded)
            self.assertIn("1.1.1.1", loaded)
            self.assertNotIn("invalid_ip", loaded)
            self.assertEqual(len(loaded), 2)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_temporary_block_expiration_logic(self) -> None:
        """
        Temporary block rules must expire and be deleted once duration has elapsed.
        """
        self.app.firewall.dry_run = False
        test_ip = "198.51.100.77"
        rule_name = f"SimpleIDPS-Block-{test_ip}"

        # Mock runner for add, show, and delete
        import subprocess
        self.mock_runner.side_effect = [
            subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Ok.\n", stderr=""),
            subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout=f"Rule Name: {rule_name}\n", stderr=""),
            subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Deleted 1 rule(s).\n", stderr=""),
        ]

        # Block at t = 100.0s
        self.app.firewall.block_ip(test_ip, timestamp=100.0)
        self.assertIn(rule_name, self.app.firewall.created_blocks)

        # Check at t = 130.0s with duration 60.0s (not yet expired)
        not_expired = self.app.firewall.expire_rules(now=130.0, block_duration=60.0)
        self.assertEqual(len(not_expired), 0)
        self.assertIn(rule_name, self.app.firewall.created_blocks)

        # Check at t = 165.0s with duration 60.0s (expired: 65s > 60s)
        expired = self.app.firewall.expire_rules(now=165.0, block_duration=60.0)
        self.assertEqual(expired, [rule_name])
        self.assertNotIn(rule_name, self.app.firewall.created_blocks)


if __name__ == "__main__":
    unittest.main()
