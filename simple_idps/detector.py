"""
detector.py - Pure Detection Logic for Simple IDPS

This module implements the detection engine for our Intrusion Detection System.
It is completely decoupled from network capture (Scapy), operating system APIs,
and subprocess calls, making it fast, safe, and 100% deterministically testable.

Detection Capabilities:
1. PORT_SCAN: Detects horizontal or vertical port scanning (> 20 distinct destination ports in 10s).
2. TRAFFIC_BURST: Detects high-volume packet floods (> 300 packets from a single source in 5s).
3. ARP_ANOMALY: Detects IP-to-MAC address mapping changes (potential ARP spoofing/poisoning).

Threshold & Cooldown Philosophy:
- Exact threshold matching: Exactly 20 distinct ports does NOT alert; the 21st DOES.
- Cooldown suppression: Once an alert fires for a given (source, alert_type) pair,
  subsequent identical alerts are suppressed for DEFAULT_COOLDOWN seconds to prevent
  alert fatigue and log flooding.
"""

from collections import deque
import ipaddress
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# Configurable Thresholds and Windows
# ==============================================================================

# Port Scan: more than 20 distinct destination ports from one source within 10 seconds
PORT_SCAN_THRESHOLD: int = 20
PORT_SCAN_WINDOW: float = 10.0  # seconds

# Traffic Burst: more than 300 packets from one source within 5 seconds
TRAFFIC_BURST_THRESHOLD: int = 300
TRAFFIC_BURST_WINDOW: float = 5.0  # seconds

# Alert Cooldown: suppress repeat alerts for the same source and type within this period
DEFAULT_COOLDOWN: float = 10.0  # seconds


class Detector:
    """
    Stateful detection engine tracking connection patterns across sliding windows.
    """

    def __init__(
        self,
        port_scan_threshold: int = PORT_SCAN_THRESHOLD,
        port_scan_window: float = PORT_SCAN_WINDOW,
        traffic_burst_threshold: int = TRAFFIC_BURST_THRESHOLD,
        traffic_burst_window: float = TRAFFIC_BURST_WINDOW,
        cooldown: float = DEFAULT_COOLDOWN,
        local_ips: Optional[Set[str]] = None,
    ) -> None:
        """
        Initialize the detector with configurable detection thresholds.
        """
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.traffic_burst_threshold = traffic_burst_threshold
        self.traffic_burst_window = traffic_burst_window
        self.cooldown = cooldown
        self.local_ips: Set[str] = set(local_ips) if local_ips else set()

        # Sliding window for destination ports: src_ip -> deque of (timestamp, dst_port)
        self._port_history: Dict[str, deque[Tuple[float, int]]] = {}

        # Sliding window for packet rate: src_ip -> deque of timestamp
        self._burst_history: Dict[str, deque[float]] = {}

        # Known ARP table: ip_address -> mac_address
        self._arp_table: Dict[str, str] = {}

        # Alert cooldown tracking: (src_ip, alert_type) -> last_alert_timestamp
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

    def feed(
        self,
        src_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        arp_ip: Optional[str] = None,
        arp_mac: Optional[str] = None,
        timestamp: Optional[float] = None,
        dst_ip: Optional[str] = None,
        is_syn_probe: bool = True,
        local_ips: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Feed an observed network event into the detection engine.

        Parameters:
            src_ip: Source IPv4 address of IP packet (optional).
            dst_port: Destination TCP/UDP port (0-65535, optional).
            arp_ip: Sender protocol IPv4 address from an ARP packet (optional).
            arp_mac: Sender hardware MAC address from an ARP packet (optional).
            timestamp: Event time as Unix timestamp. If None, current system time is used.
            dst_ip: Destination IPv4 address of IP packet (optional).
            is_syn_probe: True if the packet is a TCP SYN probe targeting an unopened/open port.
                          Defaults to True for backwards compatibility. Non-SYN packets
                          (UDP, TCP replies like SYN-ACK, ACK, etc.) should pass False.
            local_ips: Set of local host IPv4 addresses. Outgoing traffic from these addresses
                       is ignored for remote-source traffic bursts and port scans.

        Returns:
            List of structured alert dictionaries for any newly triggered rules.
        """
        now = float(timestamp) if timestamp is not None else time.time()
        alerts: List[Dict[str, Any]] = []

        # ----------------------------------------------------------------------
        # 1. ARP Anomaly Detection (Kept strictly isolated from IP tracking)
        # ----------------------------------------------------------------------
        if arp_ip is not None and arp_mac is not None:
            arp_alert = self._process_arp(arp_ip=arp_ip, arp_mac=arp_mac, now=now)
            if arp_alert:
                alerts.append(arp_alert)

        # ----------------------------------------------------------------------
        # 2. IP Traffic Analysis (Port Scan & Traffic Burst)
        # ----------------------------------------------------------------------
        if src_ip is not None:
            normalized_src = self._validate_and_normalize_ip(src_ip)
            if normalized_src is not None:
                # Determine effective local host IP set
                effective_local_ips = local_ips if local_ips is not None else self.local_ips

                # Check if this packet was originated by the local host
                is_outgoing = bool(effective_local_ips and normalized_src in effective_local_ips)

                # 2a. Traffic Burst Check (Remote sources only):
                # Outgoing traffic from the host must not trigger remote traffic-burst alerts
                if not is_outgoing:
                    burst_alert = self._process_traffic_burst(src_ip=normalized_src, now=now)
                    if burst_alert:
                        alerts.append(burst_alert)

                # 2b. Port Scan Check:
                # - Outgoing traffic is excluded.
                # - Only TCP SYN probes directed to the host count toward this rule.
                # - Non-SYN TCP replies (e.g., SYN-ACK) and UDP traffic must pass is_syn_probe=False.
                # - If dst_ip and local_ips are given, packet must be addressed to local host.
                if (
                    not is_outgoing
                    and is_syn_probe
                    and dst_port is not None
                    and isinstance(dst_port, int)
                    and 0 <= dst_port <= 65535
                ):
                    destination_valid = True
                    if dst_ip is not None and effective_local_ips:
                        normalized_dst = self._validate_and_normalize_ip(dst_ip)
                        if normalized_dst not in effective_local_ips:
                            destination_valid = False

                    if destination_valid:
                        scan_alert = self._process_port_scan(
                            src_ip=normalized_src, dst_port=dst_port, now=now
                        )
                        if scan_alert:
                            alerts.append(scan_alert)

        return alerts

    # ==========================================================================
    # Internal Processing Methods
    # ==========================================================================

    def _validate_and_normalize_ip(self, ip_str: Any) -> Optional[str]:
        """
        Validate that the provided value is a valid IPv4 address.
        Returns the normalized string representation, or None if invalid.
        """
        if not isinstance(ip_str, str):
            return None
        try:
            addr = ipaddress.IPv4Address(ip_str.strip())
            return str(addr)
        except (ValueError, AttributeError):
            return None

    def _should_suppress_alert(self, src_ip: str, alert_type: str, now: float) -> bool:
        """
        Check if an alert should be suppressed due to the cooldown window.
        If not suppressed, records `now` as the new last alert time.
        """
        key = (src_ip, alert_type)
        last_time = self._last_alert_time.get(key)
        if last_time is not None and (now - last_time) < self.cooldown:
            return True
        self._last_alert_time[key] = now
        return False

    def _process_port_scan(
        self, src_ip: str, dst_port: int, now: float
    ) -> Optional[Dict[str, Any]]:
        """
        Update destination port sliding window for src_ip and check threshold.
        """
        if src_ip not in self._port_history:
            self._port_history[src_ip] = deque()

        queue = self._port_history[src_ip]

        # Expire events outside the sliding window
        expire_boundary = now - self.port_scan_window
        while queue and queue[0][0] <= expire_boundary:
            queue.popleft()

        # Add current event
        queue.append((now, dst_port))

        # Calculate distinct destination ports in the current window
        distinct_ports: Set[int] = {port for _, port in queue}

        # Check threshold: strictly greater than the threshold
        if len(distinct_ports) > self.port_scan_threshold:
            if not self._should_suppress_alert(src_ip, "PORT_SCAN", now):
                return {
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "src_ip": src_ip,
                    "message": (
                        f"Port scan detected: {len(distinct_ports)} distinct ports "
                        f"targeted within {self.port_scan_window:.1f}s "
                        f"(threshold > {self.port_scan_threshold})"
                    ),
                    "timestamp": now,
                    "details": {
                        "distinct_port_count": len(distinct_ports),
                        "window_seconds": self.port_scan_window,
                    },
                }

        return None

    def _process_traffic_burst(
        self, src_ip: str, now: float
    ) -> Optional[Dict[str, Any]]:
        """
        Update packet arrival sliding window for src_ip and check threshold.
        """
        if src_ip not in self._burst_history:
            self._burst_history[src_ip] = deque()

        queue = self._burst_history[src_ip]

        # Expire events outside the sliding window
        expire_boundary = now - self.traffic_burst_window
        while queue and queue[0] <= expire_boundary:
            queue.popleft()

        # Add current packet arrival
        queue.append(now)

        # Check threshold: strictly greater than the threshold
        if len(queue) > self.traffic_burst_threshold:
            if not self._should_suppress_alert(src_ip, "TRAFFIC_BURST", now):
                return {
                    "type": "TRAFFIC_BURST",
                    "severity": "MEDIUM",
                    "src_ip": src_ip,
                    "message": (
                        f"Traffic burst detected: {len(queue)} packets received "
                        f"within {self.traffic_burst_window:.1f}s "
                        f"(threshold > {self.traffic_burst_threshold})"
                    ),
                    "timestamp": now,
                    "details": {
                        "packet_count": len(queue),
                        "window_seconds": self.traffic_burst_window,
                    },
                }

        return None

    def _process_arp(
        self, arp_ip: str, arp_mac: str, now: float
    ) -> Optional[Dict[str, Any]]:
        """
        Inspect ARP sender IP and MAC mapping.
        Emits an alert if a known IP changes its MAC address.
        """
        normalized_ip = self._validate_and_normalize_ip(arp_ip)
        if not normalized_ip:
            return None

        if not isinstance(arp_mac, str) or not arp_mac.strip():
            return None

        normalized_mac = arp_mac.strip().lower()

        # Check if we have seen this IP before
        if normalized_ip not in self._arp_table:
            # First observation: record mapping, no alert emitted
            self._arp_table[normalized_ip] = normalized_mac
            return None

        old_mac = self._arp_table[normalized_ip]
        if old_mac != normalized_mac:
            # MAC address changed! Update table and alert
            self._arp_table[normalized_ip] = normalized_mac
            if not self._should_suppress_alert(normalized_ip, "ARP_ANOMALY", now):
                return {
                    "type": "ARP_ANOMALY",
                    "severity": "HIGH",
                    "src_ip": normalized_ip,
                    "message": (
                        f"ARP mapping conflict for {normalized_ip}: "
                        f"changed from {old_mac} to {normalized_mac} "
                        f"(possible ARP spoofing/poisoning)"
                    ),
                    "timestamp": now,
                    "details": {
                        "ip": normalized_ip,
                        "old_mac": old_mac,
                        "new_mac": normalized_mac,
                    },
                }

        return None

    def reset(self) -> None:
        """
        Reset all internal state. Useful for test cleanup or re-initialization.
        """
        self._port_history.clear()
        self._burst_history.clear()
        self._arp_table.clear()
        self._last_alert_time.clear()
