"""
firewall.py - Safe Windows Defender Firewall Controller

This module manages host-based firewall rules on Windows using `netsh advfirewall firewall`.
It is engineered with strong safety guardrails to prevent accidental self-lockouts,
disruption of system traffic, or modification of unrelated rules.

Key Safety Features:
1. Dry-run by default: Real firewall modification requires explicit opt-in (`dry_run=False` / `--real`).
2. Strict Address Validation: Only IPv4 addresses are accepted.
3. Fail-closed Protected Addresses: Loopback, unspecified, multicast, broadcast, local host IPs,
   and user-defined allowlists are rejected.
4. Fail-closed Discovery: If host local IP discovery fails, blocking operations are aborted.
5. Rule Specificity: All rules use the strict prefix `SimpleIDPS-Block-<ip>`. Unrelated rules
   are never touched or modified.
6. Post-Creation Verification: A block is only reported as successful if `netsh show rule`
   confirms the rule exists.
7. Session Tracking & Clean Teardown: Tracks rules created during the current run and cleanly
   removes them upon program termination (idempotent cleanup), unless `--keep-blocks` is opted into.
8. Subprocess Safety: Never uses `shell=True`. Arguments are passed as explicit token lists.
"""

import ipaddress
import logging
import socket
import subprocess
import time
from typing import Callable, List, Optional, Set, Tuple

logger = logging.getLogger("SimpleIDPS.Firewall")

# Rule prefix used to isolate our rules from any system or user rules
RULE_PREFIX = "SimpleIDPS-Block-"
DEFAULT_TIMEOUT = 5.0  # seconds for netsh command execution
DEFAULT_BLOCK_DURATION = 60.0  # seconds for temporary block rule expiration


def discover_local_ipv4_addresses() -> Tuple[Set[str], bool]:
    """
    Discover the local host's active IPv4 addresses.

    Returns:
        (set_of_ip_strings, success_flag)
        If discovery encounters an error, returns (empty_set, False).
    """
    local_ips: Set[str] = set()
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip in ip_list:
            try:
                addr = ipaddress.IPv4Address(ip)
                if not addr.is_loopback:
                    local_ips.add(str(addr))
            except ValueError:
                continue

        # Supplementary probe: UDP socket connect (does not send packets on wire)
        # to determine routing interface IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            probe_ip = s.getsockname()[0]
            local_ips.add(probe_ip)
            s.close()
        except Exception:
            pass

        # If we found at least one address or hostname resolution succeeded
        return local_ips, True
    except Exception as exc:
        logger.error("Failed to discover host IPv4 addresses: %s", exc)
        return set(), False


class FirewallController:
    """
    Manages Windows Defender Firewall rules safely via netsh advfirewall.
    """

    def __init__(
        self,
        dry_run: bool = True,
        allowlist: Optional[Set[str]] = None,
        runner: Optional[Callable[..., subprocess.CompletedProcess]] = None,
        block_duration: float = DEFAULT_BLOCK_DURATION,
    ) -> None:
        """
        Initialize the FirewallController.

        Parameters:
            dry_run: If True, log commands without making OS changes.
            allowlist: Set of IPv4 address strings that must never be blocked.
            runner: Callable matching subprocess.run (used for test mocking).
            block_duration: Lifetime in seconds for temporary block rules.
        """
        self.dry_run = dry_run
        self.runner = runner if runner is not None else subprocess.run
        self.block_duration = block_duration

        # Track rules created during THIS execution session
        self._created_rules: Set[str] = set()
        # Track creation timestamps for temporary blocks: rule_name -> created_at
        self._created_blocks: dict[str, float] = {}

        # Parse allowlist
        self.allowlist: Set[str] = set()
        if allowlist:
            for ip in allowlist:
                cleaned = ip.strip()
                if cleaned:
                    try:
                        self.allowlist.add(str(ipaddress.IPv4Address(cleaned)))
                    except ValueError:
                        logger.warning("Ignoring invalid allowlist IP: %s", cleaned)

        # Discover local host IPs
        self.local_ips, self._discovery_success = discover_local_ipv4_addresses()
        logger.debug(
            "FirewallController initialized (dry_run=%s, local_ips=%s, allowlist=%s, block_duration=%ss)",
            self.dry_run,
            self.local_ips,
            self.allowlist,
            self.block_duration,
        )

    # ==========================================================================
    # Validation & Safety Policy
    # ==========================================================================

    def is_safe_to_block(self, ip_str: str) -> Tuple[bool, str]:
        """
        Evaluate if an IP address is safe to block against safety policies.

        Returns:
            (is_safe, reason_message)
        """
        if not self._discovery_success:
            return (
                False,
                "Local IP discovery failed; failing closed to prevent accidental host self-lockout.",
            )

        # 1. Parse and validate IPv4
        try:
            addr = ipaddress.ip_address(ip_str.strip())
        except (ValueError, AttributeError):
            return False, f"'{ip_str}' is not a valid IP address."

        if not isinstance(addr, ipaddress.IPv4Address):
            return False, f"Only IPv4 addresses are supported (received {addr})."

        # 2. Reject Loopback (127.0.0.0/8)
        if addr.is_loopback:
            return False, f"Cannot block loopback address {addr}."

        # 3. Reject Unspecified (0.0.0.0)
        if addr.is_unspecified:
            return False, f"Cannot block unspecified address {addr}."

        # 4. Reject Multicast (224.0.0.0/4)
        if addr.is_multicast:
            return False, f"Cannot block multicast address {addr}."

        # 5. Reject Broadcast (255.255.255.255)
        if addr == ipaddress.IPv4Address("255.255.255.255"):
            return False, f"Cannot block broadcast address {addr}."

        # 6. Reject Laptop's own IP addresses
        if str(addr) in self.local_ips:
            return (
                False,
                f"Cannot block host's own local address {addr} (self-lockout prevention).",
            )

        # 7. Reject explicit allowlist
        if str(addr) in self.allowlist:
            return False, f"Address {addr} is explicitly allowlisted."

        return True, "Address passed safety validation."

    # ==========================================================================
    # Firewall Management Operations
    # ==========================================================================

    def _rule_name_for(self, ip: str) -> str:
        """Format the specific rule name for a blocked IP."""
        return f"{RULE_PREFIX}{ip}"

    def block_ip(self, ip: str, timestamp: Optional[float] = None) -> bool:
        """
        Block inbound traffic from the specified IPv4 address.

        In dry-run mode, logs the command that would be executed and returns False.
        In real mode, executes the netsh command, verifies rule creation, tracks the rule,
        and returns True only upon verified success.
        """
        safe, reason = self.is_safe_to_block(ip)
        if not safe:
            logger.warning("[FIREWALL REJECT] Refusing to block %s: %s", ip, reason)
            return False

        normalized_ip = str(ipaddress.IPv4Address(ip.strip()))
        rule_name = self._rule_name_for(normalized_ip)

        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={normalized_ip}",
        ]

        if self.dry_run:
            cmd_str = " ".join(cmd)
            print(f"[FIREWALL DRY RUN] Would execute: {cmd_str}")
            logger.info("[DRY RUN] Would execute: %s", cmd_str)
            return False

        # Execute command in real mode
        try:
            result = self.runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error("Timed out while adding firewall rule for %s", normalized_ip)
            return False
        except PermissionError:
            logger.error("Permission denied. Elevated (Administrator) privileges required to modify firewall.")
            return False
        except Exception as exc:
            logger.error("Error executing firewall add rule: %s", exc)
            return False

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            if "elevation" in err.lower() or "administrator" in err.lower():
                logger.error("Elevation required: Please run PowerShell as Administrator to modify firewall rules.")
            else:
                logger.error("Firewall rule creation failed (exit %d): %s", result.returncode, err)
            return False

        # Verification step: Ensure the rule actually exists before reporting success
        if not self.is_blocked(normalized_ip):
            logger.error("Rule verification failed: '%s' was not found after creation.", rule_name)
            return False

        now_ts = float(timestamp) if timestamp is not None else time.time()
        self._created_rules.add(rule_name)
        self._created_blocks[rule_name] = now_ts
        logger.info("[FIREWALL REAL] Successfully created and verified rule '%s'", rule_name)
        return True

    def unblock_ip(self, ip: str) -> bool:
        """
        Remove the firewall block rule for the specified IPv4 address.
        """
        try:
            normalized_ip = str(ipaddress.IPv4Address(ip.strip()))
        except (ValueError, AttributeError):
            logger.warning("Cannot unblock invalid IP: %s", ip)
            return False

        rule_name = self._rule_name_for(normalized_ip)
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

        if self.dry_run:
            cmd_str = " ".join(cmd)
            print(f"[FIREWALL DRY RUN] Would execute: {cmd_str}")
            logger.info("[DRY RUN] Would execute: %s", cmd_str)
            self._created_rules.discard(rule_name)
            self._created_blocks.pop(rule_name, None)
            return True

        try:
            result = self.runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            logger.error("Timed out while deleting firewall rule for %s", normalized_ip)
            return False
        except PermissionError:
            logger.error("Permission denied. Administrator privileges required to delete firewall rules.")
            return False
        except Exception as exc:
            logger.error("Error executing firewall delete rule: %s", exc)
            return False

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            # If the rule wasn't found, netsh returns nonzero; discard from our tracking
            self._created_rules.discard(rule_name)
            self._created_blocks.pop(rule_name, None)
            logger.warning("Firewall rule delete returned exit %d: %s", result.returncode, err)
            return False

        self._created_rules.discard(rule_name)
        self._created_blocks.pop(rule_name, None)
        logger.info("[FIREWALL REAL] Removed rule '%s'", rule_name)
        return True

    def is_blocked(self, ip: str) -> bool:
        """
        Check if a SimpleIDPS block rule exists in Windows Defender Firewall for this IP.
        Distinguishes our managed rule (SimpleIDPS-Block-<ip>) from unrelated rules.
        """
        try:
            normalized_ip = str(ipaddress.IPv4Address(ip.strip()))
        except (ValueError, AttributeError):
            return False

        rule_name = self._rule_name_for(normalized_ip)
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={rule_name}",
        ]

        try:
            result = self.runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT,
            )
        except Exception as exc:
            logger.debug("Error checking rule existence: %s", exc)
            return False

        if result.returncode != 0:
            return False

        # Verify that output specifically references our rule name
        output = result.stdout or ""
        return rule_name.lower() in output.lower()

    def expire_rules(
        self, now: Optional[float] = None, block_duration: Optional[float] = None
    ) -> List[str]:
        """
        Expire and remove temporary rules whose block duration has elapsed.
        Only affects rules created during this execution session.
        """
        current_time = float(now) if now is not None else time.time()
        duration = block_duration if block_duration is not None else self.block_duration
        expired_rules: List[str] = []

        for rule_name, created_at in list(self._created_blocks.items()):
            if (current_time - created_at) >= duration:
                if rule_name.startswith(RULE_PREFIX):
                    ip = rule_name[len(RULE_PREFIX):]
                    if self.unblock_ip(ip):
                        expired_rules.append(rule_name)
                else:
                    self._created_blocks.pop(rule_name, None)
                    self._created_rules.discard(rule_name)
        return expired_rules

    def cleanup(self, keep_blocks: bool = False) -> List[str]:
        """
        Idempotent teardown: Deletes all rules created during THIS execution session.

        Parameters:
            keep_blocks: If True, skips rule removal and leaves rules intact.

        Returns:
            List of rule names that were removed.
        """
        if keep_blocks:
            logger.info("Keep-blocks requested: Retaining %d rule(s)", len(self._created_rules))
            return []

        removed: List[str] = []
        rules_to_remove = list(self._created_rules)
        for rule_name in rules_to_remove:
            # Extract IP from rule name
            if rule_name.startswith(RULE_PREFIX):
                ip = rule_name[len(RULE_PREFIX):]
                if self.unblock_ip(ip):
                    removed.append(rule_name)
            else:
                self._created_rules.discard(rule_name)

        # Clear tracking sets
        self._created_rules.clear()
        self._created_blocks.clear()
        logger.info("Cleanup completed. Removed %d rule(s)", len(removed))
        return removed

    @property
    def created_rules(self) -> Set[str]:
        """Set of rule names created in this session."""
        return set(self._created_rules)

    @property
    def created_blocks(self) -> dict[str, float]:
        """Dictionary of rule_name -> created_at timestamps for this session."""
        return dict(self._created_blocks)


# Module-level default controller instance for convenience
_default_controller: Optional[FirewallController] = None


def get_default_controller(dry_run: bool = True) -> FirewallController:
    """Retrieve or create the module-level FirewallController."""
    global _default_controller
    if _default_controller is None or _default_controller.dry_run != dry_run:
        _default_controller = FirewallController(dry_run=dry_run)
    return _default_controller


def block_ip(ip: str, dry_run: bool = True) -> bool:
    """Convenience function: block an IP using default controller."""
    return get_default_controller(dry_run=dry_run).block_ip(ip)


def unblock_ip(ip: str, dry_run: bool = True) -> bool:
    """Convenience function: unblock an IP using default controller."""
    return get_default_controller(dry_run=dry_run).unblock_ip(ip)


def is_blocked(ip: str, dry_run: bool = True) -> bool:
    """Convenience function: check if an IP is blocked using default controller."""
    return get_default_controller(dry_run=dry_run).is_blocked(ip)
