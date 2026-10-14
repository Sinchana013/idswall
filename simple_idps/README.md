# Simple IDS + Firewall (Simple IDPS)

A lightweight, beginner-friendly educational Python project designed for Windows that demonstrates how an **Intrusion Detection System (IDS)** and a **Host Firewall** collaborate as an **Intrusion Detection and Prevention System (IDPS)**.

---

## 1. Project Objective & Core Concepts

In modern cybersecurity, passive visibility and active containment work together:

- **Intrusion Detection System (IDS):** Passively sniffs and inspects network packets, evaluates them against behavioral or heuristic rules, and emits alerts when anomalies or threats are detected. An IDS alone does **not** stop or alter traffic.
- **Firewall:** An enforcement point that permits or blocks packets based on deterministic rules (IP addresses, ports, directions, protocols). A firewall does **not** understand behavioral patterns like sliding-window port scans on its own.
- **Intrusion Prevention System (IPS / IDPS):** Bridges the two! When the IDS detects a qualifying high-severity threat, it triggers an automated response policy instructing the firewall to block the offending IP address in real-time.

```
       +-------------------------------------------------------+
       |                  NETWORK TRAFFIC                      |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |   1. CAPTURE: Scapy + Npcap Driver (Passively Sniff)   |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |   2. DETECT: Detector (Pure Sliding Window Engine)    |
       |      - TCP SYN Port Scans (> 20 ports in 10s)         |
       |      - Remote Traffic Bursts (> 300 packets in 5s)    |
       |      - ARP Spoofing / Mapping Conflict (Alert Only)   |
       +-------------------------------------------------------+
                                  |
                                  v
       +-------------------------------------------------------+
       |   3. ALERT & RESPONSE POLICY: Policy Classifier       |
       |      - PORT_SCAN: Eligible for automated response     |
       |      - ARP_ANOMALY: Strictly ALERT ONLY (Uncertain)   |
       |      - TRAFFIC_BURST: Strictly ALERT ONLY             |
       +-------------------------------------------------------+
                                  |
                   [If --prevent and --real enabled]
                                  v
       +-------------------------------------------------------+
       |   4. RESPOND: Windows Defender Firewall via netsh     |
       |      - Add Rule: SimpleIDPS-Block-<ip>                |
       |      - Verify Rule in Windows Filtering Platform      |
       |      - Auto-expire temporary blocks (default: 60s)    |
       |      - Clean up temporary rules on exit               |
       +-------------------------------------------------------+
```

---

## 2. Directory Structure

```
simple_idps/
├── detector.py             # Pure detection logic (sliding windows, rate limiting, independent of OS)
├── firewall.py             # Safe Windows Defender Firewall controller via netsh
├── ids.py                  # Live network packet capture CLI application (Scapy)
├── demo.py                 # 100% deterministic, offline simulation demo (runs without admin or Npcap)
├── allowlist.txt           # Example trusted IPv4 addresses and ipconfig instructions
├── requirements.txt        # Minimal external dependencies (Scapy only)
├── .gitignore              # Ignores venvs, cache, and simple_idps.log
├── README.md               # Architecture, setup, safety, and tutorials
└── tests/
    ├── __init__.py
    ├── test_detector.py    # Unit tests for sliding windows, thresholds, and ARP tracking
    ├── test_firewall.py    # Unit tests for firewall safety policies and mocked subprocess calls
    └── test_ids.py         # Unit tests for packet parsing, TCP heuristics, and response policies
```

---

## 3. Key Detection & Prevention Improvements

### A. Reducing Port-Scan False Positives (TCP SYN Probe Heuristic)
- **The Problem:** In a naïve port-scan detector, every packet sent to a different destination port counts as a scan. When your laptop browses websites, remote web servers send return traffic from ports 80/443 to various ephemeral ports on your computer. A naïve IDS flags the remote web server as an attacker!
- **The Solution:** The IDPS identifies likely TCP port probes using the standard TCP handshake heuristic:
  1. The TCP `SYN` flag must be set and the `ACK` flag must be unset (`SYN=1, ACK=0`).
  2. The packet destination must be one of the **laptop’s own local IPv4 addresses**.
  3. Outgoing packets originating from the laptop are excluded.
  4. Ordinary TCP replies (such as `SYN-ACK` or `ACK` data packets) and UDP packets do **not** count toward the TCP SYN port-scan rule.
- **Important Note:** This is a focused heuristic for TCP SYN scans (often called "stealth scans"). Other scan methods, such as UDP scans or application-level crawls, fall outside the scope of this specific rule.

### B. Why ARP Anomalies Are Always Alert-Only
- **The Problem:** In an ARP spoofing attack (such as `arpspoof` or `Ettercap`), an attacker broadcasts fake ARP messages claiming that the default gateway's IP belongs to the attacker's MAC address.
- **The Danger of Blocking:** The IP address observed in an ARP conflict alert is typically the **victim or the default gateway**, not the attacker’s real IP address! If the firewall automatically blocked `192.168.1.1` (the router), the laptop would instantly disconnect itself from the Internet.
- **Enforcement Boundary:** A host-based IP firewall filters Layer 3 traffic. It cannot solve or block Layer 2 ARP frame poisoning. Therefore, ARP anomaly alerts are classified as **ALERT ONLY** with the notification:
  ```
  [HIGH] ARP_ANOMALY from 192.168.1.1 ... Action: ALERT ONLY (source attribution is uncertain; ARP anomalies are excluded from blocking)
  ```

### C. Ignoring Laptop's Own Traffic for Traffic Bursts
- The sniffer captures both incoming and outgoing traffic on your network adapter.
- When downloading large files or streaming video, your laptop sends out hundreds of ACK packets.
- The IDPS automatically discovers local IPv4 addresses and **ignores outgoing packets from local addresses** when evaluating remote traffic-burst alerts, ensuring you are not alerted for your own web browsing.
- If local IP discovery fails, the system fails closed to **ALERT ONLY** mode to prevent accidental self-lockout.

### D. Temporary Firewall Blocks with Automatic Expiration
- Firewall block rules are not meant to be permanent. Permanent blocks create rule bloat and can permanently break legitimate services.
- The IDPS tracks the creation time of each block rule created during the session.
- By default, block rules automatically **expire after 60 seconds** (configurable via `--block-duration`). The main loop evaluates active rules and removes expired rules safely via `netsh`.
- On shutdown (`Ctrl+C`), all remaining temporary rules created in the current run are cleanly deleted.

---

## 4. Prerequisites & Installation

### Requirements
- **OS:** Windows 10 / Windows 11
- **Python:** Python 3.8+ (Python 3.12 verified)
- **Npcap (for live packet capture only):** Required by Scapy on Windows.
  > **Note:** The offline demo (`demo.py`) and all unit tests run directly in standard Python **without** Npcap and **without** administrator rights!

### Step 1: Setting up Virtual Environment (PowerShell)

Open PowerShell in the project directory:

```powershell
# Navigate into the project folder
cd simple_idps

# Create a virtual environment
python -m venv venv

# If PowerShell restricts running scripts, allow it for the current process:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Activate the virtual environment
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies

```powershell
pip install -r requirements.txt
```

### Step 3: Install Npcap (For Live Capture Only)
If you wish to sniff live traffic from your physical network adapter with `ids.py`:
1. Download **Npcap** from [https://npcap.com/](https://npcap.com/).
2. Run the installer and check the box: **"Install Npcap in WinPcap API-compatible Mode"**.
3. Finish the installation.

---

## 5. Running the Offline Simulation (`demo.py`)

The offline demo runs deterministically without Npcap, without administrator privileges, and without modifying your system firewall.

```powershell
python demo.py
```

### What `demo.py` Simulates:
1. **Normal Traffic:** Simulates benign web browsing (HTTP/HTTPS) and DNS requests from a test client (`192.0.2.10`). Output: **0 alerts**.
2. **Port Scan Attack & Safe Expiry:**
   - Filters out non-SYN probe packets (UDP and TCP replies).
   - Simulates 21 distinct incoming TCP SYN probes to the host IP.
   - Triggers `[HIGH] PORT_SCAN`.
   - Initiates dry-run block for attacker (`198.51.100.55`).
   - Fast-forwards time past 60s and demonstrates verified **automatic block expiration**.
3. **Traffic Burst:** Simulates a flood from `198.51.100.66` sending 305 packets within 2 seconds.
   - Triggers `[MEDIUM] TRAFFIC_BURST`.
   - Classified as **ALERT ONLY** (not eligible for automated blocking).
4. **ARP Spoofing:** Gateway IP `192.0.2.1` changes MAC addresses.
   - Triggers `[HIGH] ARP_ANOMALY`.
   - Classified as **ALERT ONLY** (source attribution uncertain; preventing self/gateway lockout).

---

## 6. Running the Unit Tests

The test suite runs using Python's standard library `unittest` module:

```powershell
# Run all 32 tests across all modules
python -m unittest discover tests -v

# Or run individual test modules:
python -m unittest tests/test_detector.py
python -m unittest tests/test_firewall.py
python -m unittest tests/test_ids.py
```

### Safety Guarantee in Tests:
- `tests/test_firewall.py` and `tests/test_ids.py` use mocked subprocess and packet objects. **They never invoke netsh and never alter your Windows Firewall rules.**
- `tests/test_detector.py` uses fixed timestamps for 100% deterministic execution without `time.sleep()`.

---

## 7. Live Packet Capture (`ids.py`)

Live packet sniffing requires **Administrator privileges** so the Npcap driver can open raw sockets on your network adapter.

### Step 1: List Network Interfaces
Open PowerShell as Administrator and run:

```powershell
python ids.py --list-ifaces
```

This prints all available network adapters with their descriptions and IP addresses. Note the name or GUID of your active adapter (e.g., `Wi-Fi` or `Ethernet`).

### Step 2: Finding Your Network IPs (`ipconfig`)
To configure allowlists and verify local settings on Windows:
```cmd
ipconfig /all
```
Look for your active adapter:
- **IPv4 Address:** e.g., `192.168.1.50` (your laptop's IP, automatically excluded from remote burst rules).
- **Default Gateway:** e.g., `192.168.1.1` (your router IP).
- **DNS Servers:** e.g., `192.168.1.1` or `8.8.8.8`.

### Step 3: Creating and Using an Allowlist
Create a file called `allowlist.txt` with trusted IPs:
```text
# Trusted local gateway
192.168.1.1
# Trusted DNS server
1.1.1.1
# Trusted admin workstation
192.168.1.200
```
Run `ids.py` with `--allowlist`:
```powershell
python ids.py --allowlist allowlist.txt
```

### Step 4: Understanding `--prevent` vs `--real`
To prevent accidents, the IDPS implements a two-key safety interlock:

| Mode | Command | Behavior |
| :--- | :--- | :--- |
| **Alert Only** | `python ids.py` | Emits alert logs only. No firewall commands are planned or executed. |
| **Dry Run Prevention** | `python ids.py --prevent` | Evaluates response policies for qualifying alerts and logs the exact `netsh` command it *would* execute without touching the OS firewall. |
| **Real Firewall Modification** | `python ids.py --prevent --real` | **Actively adds block rules** to Windows Defender Firewall. Rules automatically expire after `--block-duration` (default: 60s). Requires Administrator privileges. |

---

## 8. Inspecting the Log File (`simple_idps.log`)

The application automatically records all security events, alerts, policy decisions, firewall actions, and rule expirations to a persistent log file:
- **Location:** `simple_idps/simple_idps.log`
- **Contents:** Clean timestamps, severity, source IP, policy actions, and verification status.
- **Privacy:** Packet payloads and credentials are never logged.

To view the log file in PowerShell:
```powershell
Get-Content simple_idps.log -Tail 20
```

---

## 9. Manual Firewall Inspection & Cleanup via Windows Commands

If you ever need to manually verify or remove rules created by this program:

```powershell
# 1. List all rules created by SimpleIDPS:
netsh advfirewall firewall show rule name=all | Select-String "SimpleIDPS-Block-"

# 2. View details of a specific blocked IP:
netsh advfirewall firewall show rule name="SimpleIDPS-Block-198.51.100.55"

# 3. Manually delete a specific rule:
netsh advfirewall firewall delete rule name="SimpleIDPS-Block-198.51.100.55"

# 4. Remove all SimpleIDPS rules:
netsh advfirewall firewall delete rule name="SimpleIDPS-Block-*"
`
