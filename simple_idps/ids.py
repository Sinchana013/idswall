"""
ids.py - Live Packet Capture and Intrusion Detection Application

This is the command-line entrypoint for live network monitoring. It binds
Scapy's packet sniffing engine to the pure detection logic in `detector.py`
and the defensive enforcement policies in `firewall.py`.

NETWORKING & SECURITY CONCEPTS (IMPORTANT LIMITATION):
- A packet visible to Scapy is not necessarily traffic that Windows Defender Firewall
  can block. Scapy captures packets directly from the network adapter via Npcap driver hooks.
  Windows Defender Firewall, by contrast, enforces filtering at the Windows Filtering
  Platform (WFP) network layer.
- If traffic is passing through your adapter destined for another machine (e.g., in promiscuous
  mode on a shared hub or bridged interface), your host firewall cannot drop it for the destination
  host. The host firewall protects *this machine* at its local enforcement boundary.

Usage Examples:
    # 1. Detection only (dry-run, no blocking):
    python ids.py

    # 2. Inspect available network interfaces:
    python ids.py --list-ifaces

    # 3. Simulated response (shows what would be blocked without touching firewall):
    python ids.py --prevent

    # 4. Real enforcement (requires Run as Administrator):
    python ids.py --prevent --real

    # 5. Using a custom allowlist file:
    python ids.py --allowlist allowlist.txt
"""

import argparse
import ipaddress
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# Attempt Scapy import with graceful failure for beginner friendliness
try:
    from scapy.all import (  # type: ignore
        ARP,
        IP,
        TCP,
        UDP,
        conf,
        get_if_list,
        sniff,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

    # Fallback dummy class types for offline testing without Scapy installed
    class ARP:  # type: ignore
        pass

    class IP:  # type: ignore
        pass

    class TCP:  # type: ignore
        pass

    class UDP:  # type: ignore
        pass

from detector import Detector
from firewall import FirewallController

LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simple_idps.log")

# Configure logging to both console and persistent log file
logger = logging.getLogger("SimpleIDPS")
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
)
logger.addHandler(console_handler)

# Persistent file handler
file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
)
logger.addHandler(file_handler)

# Prevent duplicate log messages
logger.propagate = False

# Explicit classification: Only PORT_SCAN alerts are eligible for automated firewall blocking
BLOCK_ELIGIBLE_ALERT_TYPES = {"PORT_SCAN"}


def load_allowlist(filepath: str) -> Set[str]:
    """
    Load trusted IPv4 addresses from a plain-text file.
    Ignores blank lines and comments starting with '#'.
    Fails safely if the file cannot be accessed.
    """
    allowlist: Set[str] = set()
    if not os.path.exists(filepath):
        logger.error("Allowlist file not found: %s", filepath)
        print(f"[ERROR] Allowlist file not found: {filepath}")
        sys.exit(1)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                # Strip inline comments and whitespace
                line = raw_line.split("#")[0].strip()
                if not line:
                    continue
                try:
                    addr = ipaddress.IPv4Address(line)
                    allowlist.add(str(addr))
                except ValueError:
                    logger.warning(
                        "Ignoring invalid IP in allowlist (%s:%d): '%s'",
                        filepath,
                        line_no,
                        raw_line.strip(),
                    )
    except Exception as exc:
        logger.error("Error reading allowlist file '%s': %s", filepath, exc)
        print(f"[ERROR] Could not read allowlist file '{filepath}': {exc}")
        sys.exit(1)

    logger.info("Loaded %d trusted IP(s) from allowlist: %s", len(allowlist), filepath)
    return allowlist


def list_interfaces() -> None:
    """Print available Scapy network capture interfaces and exit."""
    if not SCAPY_AVAILABLE:
        print_missing_scapy_error()
        sys.exit(1)

    print("\nAvailable Network Interfaces for Capture:")
    print("-" * 70)
    try:
        if_list = get_if_list()
        for idx, iface in enumerate(if_list, start=1):
            details = getattr(conf.ifaces, "get", lambda x: None)(iface)
            desc = details.description if details and hasattr(details, "description") else ""
            ip = details.ip if details and hasattr(details, "ip") else "No IP"
            print(f"[{idx:>2}] {iface}")
            if desc or ip:
                print(f"     Description: {desc} | IP: {ip}")
    except Exception as exc:
        print(f"[ERROR] Failed to enumerate interfaces: {exc}")
        print("Note: If Npcap is missing, download and install it from https://npcap.com/")
    print("-" * 70)


def print_missing_scapy_error() -> None:
    """Display instructions when Scapy is missing."""
    print("\n" + "!" * 70)
    print("[ERROR] Scapy is not installed.")
    print("Please install the required Python packages:")
    print("    pip install -r requirements.txt")
    print("\nPrerequisites on Windows:")
    print("1. Install Npcap from https://npcap.com/")
    print("   (Ensure 'WinPcap API-compatible Mode' is checked during setup).")
    print("2. Run PowerShell or Windows Terminal as Administrator for live packet capture.")
    print("!" * 70 + "\n")


class LiveIDPS:
    """
    Coordinates live packet capturing, passing to detector, and executing response policy.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        prevent: bool = False,
        real: bool = False,
        allowlist: Optional[Set[str]] = None,
        keep_blocks: bool = False,
        block_duration: float = 60.0,
    ) -> None:
        self.iface = iface
        self.prevent = prevent
        self.real = real
        self.keep_blocks = keep_blocks

        # Initialize firewall controller first to discover local host IPs
        # Dry-run is enforced unless both --prevent and --real are specified
        self.dry_run = not (self.prevent and self.real)
        self.firewall = FirewallController(
            dry_run=self.dry_run,
            allowlist=allowlist,
            block_duration=block_duration,
        )

        self.local_ips: Set[str] = set(self.firewall.local_ips)
        self.discovery_success: bool = self.firewall._discovery_success

        if not self.discovery_success:
            logger.warning(
                "Local IP discovery failed. Outgoing host traffic cannot be reliably separated; "
                "automatic blocking is disabled for safety (fail-closed alert-only mode)."
            )

        # Initialize detector with known local host IPs
        self.detector = Detector(local_ips=self.local_ips)

        self.packet_count = 0
        self.alert_count = 0
        self._last_expiry_check = 0.0

    def evaluate_response_policy(self, alert: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Evaluate whether an alert qualifies for active firewall blocking.

        Safety Policies:
        1. ARP Anomaly: Always ALERT ONLY. The IP whose mapping changed may be the victim
           or default gateway. Blocking it would cause network disruption and does not prevent ARP spoofing.
        2. Traffic Burst: ALERT ONLY under initial response policy.
        3. Port Scan: Confirmed port scan probes directed at the host qualify for response policy.
        4. Local IP Discovery Failure: Fails closed to ALERT ONLY to avoid self-lockout.
        """
        alert_type = alert.get("type", "UNKNOWN")

        if alert_type == "ARP_ANOMALY":
            return (
                False,
                "ALERT ONLY (source attribution is uncertain; ARP anomalies are excluded from blocking)",
            )

        if alert_type not in BLOCK_ELIGIBLE_ALERT_TYPES:
            return (
                False,
                f"ALERT ONLY ({alert_type} is not eligible for automatic blocking under current policy)",
            )

        if not self.discovery_success:
            return (
                False,
                "ALERT ONLY (local IP discovery failed; failing closed to prevent host self-lockout)",
            )

        return True, "Eligible for automatic firewall response policy"

    def process_packet(self, packet: Any) -> None:
        """
        Scapy packet callback. Normalizes protocol data and feeds to detector.
        """
        self.packet_count += 1
        now = time.time()

        # Periodic check for expiring temporary firewall rules (runs ~once per second)
        if (now - self._last_expiry_check) >= 1.0:
            self._last_expiry_check = now
            expired = self.firewall.expire_rules(now=now)
            if expired:
                print(f"\n[*] Expired {len(expired)} temporary block rule(s): {', '.join(expired)}")
                logger.info("Expired %d temporary rule(s): %s", len(expired), ", ".join(expired))

        try:
            # 1. ARP Inspection (Layer 2)
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                arp_ip = getattr(arp_layer, "psrc", None)
                arp_mac = getattr(arp_layer, "hwsrc", None)
                alerts = self.detector.feed(arp_ip=arp_ip, arp_mac=arp_mac, timestamp=now)
                for alert in alerts:
                    self._handle_alert(alert)

            # 2. IPv4 Inspection (Layer 3 & 4)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = getattr(ip_layer, "src", None)
                dst_ip = getattr(ip_layer, "dst", None)

                # Ignore outgoing packets generated by the laptop's own local IPs
                # This prevents host downloads or streaming from triggering remote traffic-burst or port-scan rules
                if src_ip and src_ip in self.local_ips:
                    return

                # 2a. Remote Traffic Burst Check (any remote packet arrival)
                burst_alerts = self.detector.feed(src_ip=src_ip, timestamp=now)
                for alert in burst_alerts:
                    self._handle_alert(alert)

                # 2b. TCP SYN Port Scan Check (only incoming TCP probes directed to local host)
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    # Heuristic for TCP port probe: TCP SYN flag set and ACK flag unset
                    flags_val = int(tcp.flags)
                    is_syn_probe = (flags_val & 0x02 != 0) and (flags_val & 0x10 == 0)
                    is_to_local = bool(dst_ip and dst_ip in self.local_ips)

                    # Only count as evidence if it is a SYN probe directed to one of this laptop's IPs
                    if is_syn_probe and is_to_local:
                        scan_alerts = self.detector.feed(
                            src_ip=src_ip,
                            dst_port=int(tcp.dport),
                            timestamp=now,
                            dst_ip=dst_ip,
                            is_syn_probe=True,
                        )
                        for alert in scan_alerts:
                            self._handle_alert(alert)

        except Exception as exc:
            # Safely ignore malformed or partially decoded packets
            logger.debug("Packet parsing error: %s", exc)
            return

    def _handle_alert(self, alert: Dict[str, Any]) -> None:
        """
        Handle a newly triggered alert and apply response policy.
        """
        self.alert_count += 1
        t_str = time.strftime("%H:%M:%S", time.localtime(alert["timestamp"]))
        severity = alert["severity"]
        alert_type = alert["type"]
        src = alert["src_ip"]
        msg = alert["message"]

        # Formatted alert line
        log_line = f"[{t_str}] [{severity}] {alert_type} from {src} - {msg}"
        print(f"\n[ALERT] {log_line}")

        # Evaluate response policy
        is_eligible, policy_reason = self.evaluate_response_policy(alert)

        if not is_eligible:
            print(f"        -> Action: {policy_reason}")
            logger.info("Alert %s from %s -> Action: %s", alert_type, src, policy_reason)
            return

        # Alert is eligible for blocking (confirmed PORT_SCAN)
        if not self.prevent:
            action_desc = "[ALERT ONLY] Prevention disabled. Use --prevent to enable response."
            print(f"        -> Action: {action_desc}")
            logger.info("Alert %s from %s -> Action: %s", alert_type, src, action_desc)
        elif self.dry_run:
            # --prevent was provided, but --real was not
            print(f"        -> Action: [DRY RUN] {alert_type} threshold met. Testing block policy...")
            self.firewall.block_ip(src)
            print(f"        -> Note: Pass --real with Administrator privileges to actively block in Windows Firewall.")
            logger.info("Alert %s from %s -> Action: [DRY RUN] Planned block SimpleIDPS-Block-%s", alert_type, src, src)
        else:
            # Both --prevent and --real provided
            print(f"        -> Action: [ENFORCING BLOCK] Blocking {src} via Windows Defender Firewall...")
            blocked = self.firewall.block_ip(src)
            if blocked:
                print(f"        -> Result: [BLOCKED] Successfully created and verified rule SimpleIDPS-Block-{src}")
                logger.info("Alert %s from %s -> Result: [BLOCKED] Created rule SimpleIDPS-Block-%s", alert_type, src, src)
            else:
                print(f"        -> Result: [SKIPPED/FAILED] Could not block {src} (check safety policy or permissions)")
                logger.warning("Alert %s from %s -> Result: [SKIPPED/FAILED] Could not block %s", alert_type, src, src)

    def run(self) -> None:
        """
        Start the live sniffing loop.
        """
        if not SCAPY_AVAILABLE:
            print_missing_scapy_error()
            sys.exit(1)

        # Validate interface if user specified one
        if self.iface:
            valid_interfaces = get_if_list()
            if self.iface not in valid_interfaces:
                print(f"\n[ERROR] Interface '{self.iface}' not found in available interfaces.")
                print("Available interfaces:")
                for i in valid_interfaces:
                    print(f"  - {i}")
                print("\nUse --list-ifaces to see friendly descriptions.")
                sys.exit(1)

        print("\n" + "=" * 70)
        print(" SIMPLE IDS + FIREWALL (IDPS) - LIVE MONITORING")
        print("=" * 70)
        print(f"Capture Interface : {self.iface if self.iface else 'Default (All Adapters)'}")
        print(f"Prevention Mode   : {'ENABLED' if self.prevent else 'DISABLED (Alert-only)'}")
        print(f"Enforcement Mode  : {'REAL (Windows Firewall rules modified)' if self.real and self.prevent else 'DRY RUN (Safe)'}")
        print(f"Cleanup on Exit   : {'Retain rules (--keep-blocks)' if self.keep_blocks else 'Remove temporary rules (Default)'}")
        print("-" * 70)
        print("[*] Listening for network packets... Press Ctrl+C to stop.")

        try:
            sniff(
                iface=self.iface,
                prn=self.process_packet,
                store=False,
            )
        except PermissionError:
            print("\n[ERROR] Packet capture requires administrative privileges.")
            print("Please run PowerShell or Command Prompt as Administrator.")
            sys.exit(1)
        except Exception as exc:
            err_str = str(exc)
            if "pcap" in err_str.lower() or "winpcap" in err_str.lower() or "wpcap" in err_str.lower():
                print(f"\n[ERROR] Packet capture driver error: {exc}")
                print("Npcap is required on Windows for packet capture.")
                print("Download and install Npcap from: https://npcap.com/")
            else:
                print(f"\n[ERROR] Capture terminated unexpectedly: {exc}")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        """
        Clean shutdown routine to clean up firewall rules.
        """
        print("\n" + "-" * 70)
        print(f"[*] Stopping capture session. Total packets: {self.packet_count}, Total alerts: {self.alert_count}")
        removed = self.firewall.cleanup(keep_blocks=self.keep_blocks)
        if removed:
            print(f"[*] Removed {len(removed)} temporary firewall rule(s): {', '.join(removed)}")
        elif not self.keep_blocks and not self.dry_run:
            print("[*] No temporary rules to remove.")
        print("[*] IDPS shutdown cleanly.")


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Simple IDS + Firewall - Lightweight Educational Intrusion Detection & Prevention System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g., 'Ethernet' or GUID). Default: sniff on all.",
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--prevent",
        action="store_true",
        help="Enable the IPS response policy for qualifying HIGH severity alerts.",
    )
    parser.add_argument(
        "--real",
        action="store_true",
        help="Allow actual Windows Defender Firewall modifications. (Default: dry-run only).",
    )
    parser.add_argument(
        "--allowlist",
        type=str,
        default=None,
        help="Path to plain-text file with trusted IPv4 addresses to never block.",
    )
    parser.add_argument(
        "--keep-blocks",
        action="store_true",
        help="Preserve firewall rules created in this run after shutdown. (Default: removes them on exit).",
    )
    parser.add_argument(
        "--block-duration",
        type=float,
        default=60.0,
        help="Temporary firewall block duration in seconds before automatic expiration (default: 60.0s).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    if args.list_ifaces:
        list_interfaces()
        return

    allowlist_ips: Optional[Set[str]] = None
    if args.allowlist:
        allowlist_ips = load_allowlist(args.allowlist)

    app = LiveIDPS(
        iface=args.iface,
        prevent=args.prevent,
        real=args.real,
        allowlist=allowlist_ips,
        keep_blocks=args.keep_blocks,
        block_duration=args.block_duration,
    )

    # Register signal handler for clean shutdown
    def sig_handler(sig, frame):
        # Scapy sniff loop will terminate on next iteration or exception
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)

    app.run()


if __name__ == "__main__":
    main()
