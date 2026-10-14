"""
test_firewall.py - Safe Unit Tests for Firewall Controller

CRITICAL SAFETY GUARANTEE:
These tests use mocked subprocess calls exclusively. Under no circumstances
do these tests execute actual Windows netsh commands or alter Windows Firewall rules.
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add simple_idps directory to path
parent_dir = Path(__file__).resolve().parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from firewall import FirewallController, RULE_PREFIX


class TestFirewallController(unittest.TestCase):
    """Test suite for FirewallController safety policies and command generation."""

    def setUp(self) -> None:
        """Set up mocked controller for testing."""
        self.mock_runner = MagicMock()
        # Create controller with known local IP and mock runner
        with patch("firewall.discover_local_ipv4_addresses") as mock_disc:
            mock_disc.return_value = ({"192.168.1.10"}, True)
            self.controller = FirewallController(
                dry_run=True,
                allowlist={"10.0.0.1"},
                runner=self.mock_runner,
            )

    def test_dry_run_mode_does_not_invoke_subprocess(self) -> None:
        """In dry-run mode (default), block_ip must NEVER invoke subprocess.run."""
        test_ip = "198.51.100.55"
        self.assertTrue(self.controller.dry_run)

        result = self.controller.block_ip(test_ip)

        # In dry run, block_ip returns False because no real OS rule was established
        self.assertFalse(result)
        # Verify that mock_runner was never called
        self.mock_runner.assert_not_called()
        # Verify no rules are marked as created
        self.assertEqual(len(self.controller.created_rules), 0)

    def test_address_validation_and_rejections(self) -> None:
        """Verify that loopback, unspecified, multicast, broadcast, local IPs, and allowlisted IPs are rejected."""
        # 1. Loopback
        safe, reason = self.controller.is_safe_to_block("127.0.0.1")
        self.assertFalse(safe)
        self.assertIn("loopback", reason.lower())

        # 2. Unspecified
        safe, reason = self.controller.is_safe_to_block("0.0.0.0")
        self.assertFalse(safe)
        self.assertIn("unspecified", reason.lower())

        # 3. Multicast
        safe, reason = self.controller.is_safe_to_block("224.0.0.1")
        self.assertFalse(safe)
        self.assertIn("multicast", reason.lower())

        # 4. Broadcast
        safe, reason = self.controller.is_safe_to_block("255.255.255.255")
        self.assertFalse(safe)
        self.assertIn("broadcast", reason.lower())

        # 5. Local host IP
        safe, reason = self.controller.is_safe_to_block("192.168.1.10")
        self.assertFalse(safe)
        self.assertIn("host's own local address", reason.lower())

        # 6. Allowlisted IP
        safe, reason = self.controller.is_safe_to_block("10.0.0.1")
        self.assertFalse(safe)
        self.assertIn("allowlisted", reason.lower())

        # 7. Invalid string
        safe, reason = self.controller.is_safe_to_block("invalid-ip")
        self.assertFalse(safe)

        # 8. Valid external IP
        safe, reason = self.controller.is_safe_to_block("198.51.100.55")
        self.assertTrue(safe)

    def test_fail_closed_if_local_ip_discovery_fails(self) -> None:
        """If local IP discovery fails, controller must fail closed and refuse all blocking."""
        with patch("firewall.discover_local_ipv4_addresses") as mock_disc:
            mock_disc.return_value = (set(), False)  # Failed discovery
            unsafe_controller = FirewallController(dry_run=False, runner=self.mock_runner)

            safe, reason = unsafe_controller.is_safe_to_block("198.51.100.55")
            self.assertFalse(safe)
            self.assertIn("failing closed", reason.lower())

            result = unsafe_controller.block_ip("198.51.100.55")
            self.assertFalse(result)
            self.mock_runner.assert_not_called()

    def test_real_block_ip_success_with_verification(self) -> None:
        """
        In real mode, block_ip executes netsh add rule, then verifies rule existence
        via netsh show rule before reporting success.
        """
        test_ip = "198.51.100.55"
        rule_name = f"{RULE_PREFIX}{test_ip}"

        self.controller.dry_run = False

        # First call is 'add rule' (exit 0)
        # Second call is 'show rule' (exit 0, stdout containing rule_name)
        self.mock_runner.side_effect = [
            subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Ok.\n", stderr=""),
            subprocess.CompletedProcess(
                args=["netsh"],
                returncode=0,
                stdout=f"Rule Name: {rule_name}\nAction: Block\nOk.\n",
                stderr="",
            ),
        ]

        result = self.controller.block_ip(test_ip)
        self.assertTrue(result)
        self.assertIn(rule_name, self.controller.created_rules)
        self.assertEqual(self.mock_runner.call_count, 2)

        # Verify exact command tokens for add rule
        add_call_args = self.mock_runner.call_args_list[0][0][0]
        self.assertEqual(
            add_call_args,
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={test_ip}",
            ],
        )

    def test_block_ip_fails_if_verification_fails(self) -> None:
        """If add rule succeeds but show rule does not confirm rule existence, report failure."""
        test_ip = "198.51.100.55"
        self.controller.dry_run = False

        # Add rule succeeds, but show rule returns exit code 1 / not found
        self.mock_runner.side_effect = [
            subprocess.CompletedProcess(args=["netsh"], returncode=0, stdout="Ok.\n", stderr=""),
            subprocess.CompletedProcess(
                args=["netsh"],
                returncode=1,
                stdout="No rules match the specified criteria.\n",
                stderr="",
            ),
        ]

        result = self.controller.block_ip(test_ip)
        self.assertFalse(result, "Block must report False if post-creation verification fails")
        self.assertEqual(len(self.controller.created_rules), 0)

    def test_is_blocked_distinguishes_managed_rules(self) -> None:
        """is_blocked returns True only when netsh specifically returns the managed rule name."""
        test_ip = "198.51.100.55"
        rule_name = f"{RULE_PREFIX}{test_ip}"

        # 1. Output contains our rule
        self.mock_runner.return_value = subprocess.CompletedProcess(
            args=["netsh"],
            returncode=0,
            stdout=f"Rule Name: {rule_name}\nAction: Block\n",
            stderr="",
        )
        self.assertTrue(self.controller.is_blocked(test_ip))

        # 2. Output contains unrelated rule
        self.mock_runner.return_value = subprocess.CompletedProcess(
            args=["netsh"],
            returncode=0,
            stdout="Rule Name: Core Networking - DNS (UDP-In)\n",
            stderr="",
        )
        self.assertFalse(self.controller.is_blocked(test_ip))

        # 3. Netsh returned error
        self.mock_runner.return_value = subprocess.CompletedProcess(
            args=["netsh"],
            returncode=1,
            stdout="No rules match the specified criteria.\n",
            stderr="",
        )
        self.assertFalse(self.controller.is_blocked(test_ip))

    def test_unblock_ip_removes_rule_and_tracking(self) -> None:
        """unblock_ip executes netsh delete rule and removes from session tracking."""
        test_ip = "198.51.100.55"
        rule_name = f"{RULE_PREFIX}{test_ip}"
        self.controller.dry_run = False
        self.controller._created_rules.add(rule_name)

        self.mock_runner.return_value = subprocess.CompletedProcess(
            args=["netsh"], returncode=0, stdout="Deleted 1 rule(s).\nOk.\n", stderr=""
        )

        result = self.controller.unblock_ip(test_ip)
        self.assertTrue(result)
        self.assertNotIn(rule_name, self.controller.created_rules)

        del_args = self.mock_runner.call_args[0][0]
        self.assertEqual(
            del_args,
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        )

    def test_cleanup_is_idempotent(self) -> None:
        """Calling cleanup twice must be safe and only delete each rule once."""
        rule_1 = f"{RULE_PREFIX}198.51.100.55"
        rule_2 = f"{RULE_PREFIX}198.51.100.56"
        self.controller.dry_run = False
        self.controller._created_rules.add(rule_1)
        self.controller._created_rules.add(rule_2)

        self.mock_runner.return_value = subprocess.CompletedProcess(
            args=["netsh"], returncode=0, stdout="Deleted 1 rule(s).\nOk.\n", stderr=""
        )

        # First cleanup
        removed = self.controller.cleanup(keep_blocks=False)
        self.assertEqual(len(removed), 2)
        self.assertEqual(len(self.controller.created_rules), 0)

        # Second cleanup (idempotent: does nothing)
        removed_again = self.controller.cleanup(keep_blocks=False)
        self.assertEqual(len(removed_again), 0)

    def test_subprocess_timeout_and_exceptions_handled_safely(self) -> None:
        """Subprocess timeouts and exceptions must be caught and return False without crashing."""
        self.controller.dry_run = False

        # TimeoutExpired
        self.mock_runner.side_effect = subprocess.TimeoutExpired(cmd="netsh", timeout=5.0)
        self.assertFalse(self.controller.block_ip("198.51.100.55"))

        # PermissionError
        self.mock_runner.side_effect = PermissionError("Access denied")
        self.assertFalse(self.controller.block_ip("198.51.100.55"))


if __name__ == "__main__":
    unittest.main()
