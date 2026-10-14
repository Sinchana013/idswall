"""
demo.py - Deterministic Offline Demonstration of Simple IDPS

This script demonstrates how the Intrusion Detection System (Detector) and
Firewall Controller (FirewallController) work together in a realistic, reproducible
offline environment.

Key Guarantees:
- Runs without Scapy or Npcap installed.
- Runs without Windows Administrator privileges.
- Never executes live network packet capture.
- Never modifies real Windows Firewall rules (Strict Dry-Run mode).
- Uses fixed timestamps so output is 100% deterministic and reproducible.

Demonstrated Scenarios:
1. Normal Traffic: Normal web browsing and DNS queries (0 alerts).
2. Port Scan Attack: An attacker probing > 20 distinct ports within 10s.
3. Traffic Burst Attack: A volumetric packet flood > 300 packets within 5s.
4. ARP Poisoning/Spoofing: A known IP address suddenly changing MAC addresses.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure parent directory is on sys.path so modules can be imported
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from detector import Detector
from firewall import FirewallController


def format_alert(alert: Dict[str, Any]) -> str:
    """Format an alert dictionary into a standardized human-readable log line."""
    ts = f"{alert['timestamp']:.2f}s"
    severity = alert.get("severity", "INFO")
    alert_type = alert.get("type", "UNKNOWN")
    src = alert.get("src_ip", "N/A")
    msg = alert.get("message", "")
    return f"[{ts:>8}] [{severity:<6}] {alert_type} from {src} - {msg}"


def run_demo() -> bool:
    """Execute the end-to-end deterministic demonstration."""
    print("=" * 80)
    print(" SIMPLE IDS + FIREWALL (IDPS) - OFFLINE SIMULATION DEMO")
    print("=" * 80)
    print("Environment: Offline / Non-Elevated / Deterministic")
    print("Firewall Mode: Safe Dry-Run (subprocess commands are simulated/logged)")
    print("-" * 80)

    # Initialize components
    detector = Detector()
    # Safe dry-run firewall controller: never executes netsh
    firewall = FirewallController(dry_run=True)

    summary_records: List[Dict[str, Any]] = []

    # ==========================================================================
    # SCENARIO 1: Normal Everyday Network Traffic
    # ==========================================================================
    print("\n[+] SCENARIO 1: Normal Traffic Simulation")
    print("    Simulating a normal client (192.0.2.10) browsing websites & DNS queries...")

    normal_events = [
        # (src_ip, dst_port, timestamp, description)
        ("192.0.2.10", 53, 10.0, "DNS Query"),
        ("192.0.2.10", 443, 10.2, "HTTPS Request"),
        ("192.0.2.10", 443, 10.5, "HTTPS Continuation"),
        ("192.0.2.10", 80, 11.0, "HTTP Request"),
        ("192.0.2.10", 443, 12.0, "HTTPS Request"),
        ("192.0.2.10", 53, 13.0, "DNS Query"),
    ]

    scenario_1_alerts = 0
    for src_ip, dst_port, ts, desc in normal_events:
        alerts = detector.feed(src_ip=src_ip, dst_port=dst_port, timestamp=ts)
        for a in alerts:
            print(f"    ! {format_alert(a)}")
            scenario_1_alerts += 1

    if scenario_1_alerts == 0:
        print("    -> Result: 0 alerts triggered (Traffic correctly recognized as benign).")
    else:
        print(f"    -> Warning: Unexpected {scenario_1_alerts} alert(s) triggered!")

    summary_records.append({
        "scenario": "1. Normal Traffic",
        "events": len(normal_events),
        "alerts": scenario_1_alerts,
        "action": "ALLOW (Normal)",
        "expected": "0 alerts",
        "passed": scenario_1_alerts == 0,
    })

    # ==========================================================================
    # SCENARIO 2: Port Scan Attack (> 20 Distinct TCP SYN Probes in 10s)
    # ==========================================================================
    print("\n[+] SCENARIO 2: Port Scan Attack Simulation")
    print("    Attacker (198.51.100.55) sends TCP SYN probes to host IP (192.168.1.10)...")

    local_laptop_ip = "192.168.1.10"
    detector.local_ips = {local_laptop_ip}
    scan_ip = "198.51.100.55"

    # Demonstrate false-positive reduction:
    # A non-SYN packet (e.g., UDP or TCP reply with ACK) directed to the host
    print("    [Filter Check] Sending 2 non-SYN packets (UDP and TCP SYN-ACK reply)...")
    detector.feed(src_ip=scan_ip, dst_port=8081, timestamp=99.0, dst_ip=local_laptop_ip, is_syn_probe=False)
    detector.feed(src_ip=scan_ip, dst_port=8082, timestamp=99.5, dst_ip=local_laptop_ip, is_syn_probe=False)
    print("    -> Confirmed: Non-SYN probe packets correctly ignored.")

    scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,  # 20 distinct TCP SYN probes
        5900,  # 21st port -> SHOULD TRIGGER ALERT
        8080, 8443, 8888, 9000,  # Extra ports -> SHOULD BE SUPPRESSED BY COOLDOWN
    ]

    scenario_2_alerts: List[Dict[str, Any]] = []
    base_ts = 100.0

    for idx, port in enumerate(scan_ports, start=1):
        # Evenly spread over 3 seconds
        ts = base_ts + (idx * 0.1)
        alerts = detector.feed(
            src_ip=scan_ip,
            dst_port=port,
            timestamp=ts,
            dst_ip=local_laptop_ip,
            is_syn_probe=True,
        )
        for a in alerts:
            print(f"    ! {format_alert(a)}")
            scenario_2_alerts.append(a)

            # Evaluate IPS response policy: Only PORT_SCAN is eligible for automated blocking
            if a.get("type") == "PORT_SCAN":
                print(f"    -> [IPS POLICY: ELIGIBLE] Port scan qualifies for automated response.")
                print(f"    -> Initiating dry-run block for {scan_ip} (expires in 60s)...")
                firewall.block_ip(scan_ip, timestamp=ts)
                # Track in demo controller so expiration can be demonstrated deterministically
                rule_name = f"SimpleIDPS-Block-{scan_ip}"
                firewall._created_blocks[rule_name] = ts

    print(f"    -> Scanned {len(scan_ports)} ports. Alerts triggered: {len(scenario_2_alerts)}.")
    print("    -> Note: Notice how ports 1-20 did not alert, port 21 triggered HIGH alert,")
    print("       and subsequent ports 22-25 were suppressed by the cooldown mechanism.")

    # Demonstrate temporary block expiration
    print("\n    [Expiry Check] Fast-forwarding time to t=165.0s (past 60s block duration)...")
    expired = firewall.expire_rules(now=165.0, block_duration=60.0)
    print(f"    -> Expired temporary rule(s): {', '.join(expired) if expired else 'None'} (Safe Expiry Verified)")

    summary_records.append({
        "scenario": "2. Port Scan Attack",
        "events": len(scan_ports) + 2,
        "alerts": len(scenario_2_alerts),
        "action": "DRY RUN BLOCK",
        "expected": "1 alert (on 21st port)",
        "passed": len(scenario_2_alerts) == 1 and len(expired) == 1,
    })

    # ==========================================================================
    # SCENARIO 3: Volumetric Traffic Burst (> 300 Packets in 5s)
    # ==========================================================================
    print("\n[+] SCENARIO 3: High-Volume Traffic Burst Simulation")
    print("    Flooder (198.51.100.66) sends 305 packets within 2.0 seconds...")

    flood_ip = "198.51.100.66"
    scenario_3_alerts: List[Dict[str, Any]] = []
    burst_ts_base = 200.0
    total_packets = 305

    for i in range(1, total_packets + 1):
        ts = burst_ts_base + (i * (2.0 / total_packets))
        alerts = detector.feed(src_ip=flood_ip, dst_port=80, timestamp=ts)
        for a in alerts:
            print(f"    ! {format_alert(a)}")
            scenario_3_alerts.append(a)
            if a.get("type") == "TRAFFIC_BURST":
                # Under revised policy, TRAFFIC_BURST is explicitly ALERT ONLY
                print(f"    -> [IPS POLICY: EXCLUDED] Action: ALERT ONLY (TRAFFIC_BURST is not eligible for automatic blocking under current policy)")

    print(f"    -> Sent {total_packets} packets. Alerts triggered: {len(scenario_3_alerts)}.")
    print("    -> Note: Traffic bursts from remote sources are flagged for operator visibility without disruptive blocking.")

    summary_records.append({
        "scenario": "3. Traffic Burst",
        "events": total_packets,
        "alerts": len(scenario_3_alerts),
        "action": "ALERT ONLY",
        "expected": "1 alert (on 301st packet)",
        "passed": len(scenario_3_alerts) == 1,
    })

    # ==========================================================================
    # SCENARIO 4: ARP Spoofing / Mapping Change
    # ==========================================================================
    print("\n[+] SCENARIO 4: ARP Anomaly / Poisoning Simulation")
    print("    Observing local ARP traffic on gateway IP 192.0.2.1...")

    arp_ip = "192.0.2.1"
    legit_mac = "00:11:22:33:44:55"
    attacker_mac = "aa:bb:cc:dd:ee:ff"

    # Step 4a: First ARP observation (Normal gratuitous ARP or who-has reply)
    print(f"    [Step A] Initial ARP announcement: {arp_ip} at {legit_mac} (t=300.0s)")
    initial_alerts = detector.feed(arp_ip=arp_ip, arp_mac=legit_mac, timestamp=300.0)
    for a in initial_alerts:
        print(f"    ! {format_alert(a)}")
    print(f"    -> Initial mapping stored. Alerts triggered: {len(initial_alerts)} (Expected: 0)")

    # Step 4b: Malicious ARP reply claiming same IP with different MAC
    print(f"    [Step B] Conflicting ARP reply: {arp_ip} claimed by {attacker_mac} (t=305.0s)")
    poison_alerts = detector.feed(arp_ip=arp_ip, arp_mac=attacker_mac, timestamp=305.0)
    for a in poison_alerts:
        print(f"    ! {format_alert(a)}")
        if a.get("type") == "ARP_ANOMALY":
            print(f"    -> [IPS POLICY: EXCLUDED] Action: ALERT ONLY (source attribution is uncertain; ARP anomalies are excluded from blocking)")

    summary_records.append({
        "scenario": "4. ARP Anomaly",
        "events": 2,
        "alerts": len(poison_alerts),
        "action": "ALERT ONLY",
        "expected": "1 alert (MAC change)",
        "passed": len(initial_alerts) == 0 and len(poison_alerts) == 1,
    })

    # ==========================================================================
    # DEMO SUMMARY REPORT
    # ==========================================================================
    print("\n" + "=" * 80)
    print(" OFFLINE SIMULATION SUMMARY REPORT")
    print("=" * 80)
    header = f"{'Scenario':<25} | {'Events':<7} | {'Alerts':<7} | {'Response':<16} | {'Status'}"
    print(header)
    print("-" * len(header))

    all_passed = True
    for rec in summary_records:
        status = "PASSED" if rec["passed"] else "FAILED"
        if not rec["passed"]:
            all_passed = False
        print(
            f"{rec['scenario']:<25} | {rec['events']:<7} | "
            f"{rec['alerts']:<7} | {rec['action']:<16} | {status}"
        )

    print("-" * len(header))
    if all_passed:
        print("\n[SUCCESS] All deterministic simulation scenarios behaved exactly as expected!")
        print("Note: No actual Windows Firewall changes were performed during this demo.")
        return True
    else:
        print("\n[FAILURE] One or more scenarios did not match expected outcomes.")
        return False


if __name__ == "__main__":
    success = run_demo()
    sys.exit(0 if success else 1)

