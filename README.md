# RoutePulse SOC — Real-Time Network Traffic Monitoring & IP Threat Assessment

> **B.Tech Capstone & Internship Project (Phase I)**  
> **Student:** Aman Pandey (Computer Science and Design, RR Institute of Modern Technology)  
> **Industry Mentorship:** Mr. Hitesh Kumawat, IBM India Pvt. Ltd.  
> **Prototype Origin:** [NetCalc Pro Prototype](https://net-calculator.lovable.app)

---

## 🚀 Overview

**RoutePulse SOC** consolidates scattered threat intelligence, real-time network traffic observation, and CIDR subnet calculation into a single, high-tech, unified security operations platform.

It directly solves the core problems identified in the project presentation:
- **Malicious IP Infiltration**: Rapid detection of automated bots, scanners, and brute-force actors.
- **Tool Fragmentation**: Consolidates WHOIS, ASN classification, Geolocation, Tor/Proxy detection, and Subnet calculations into one dashboard.
- **Delayed Incident Response**: Instant threat scoring (0-100) and one-click firewall perimeter blocklists.
- **Blind Spots for SMBs**: Lightweight, fast, browser-accessible architecture without needing massive, expensive enterprise SIEM licenses.

---

## 🏛️ Modular System Architecture (The 4 Layers)

As detailed in **Slide 8** of the presentation:

| Layer | Component | Implementation in Codebase |
| :--- | :--- | :--- |
| **Layer 1** | **Traffic Collection** | Web server access logs, firewall syslog events, live synthetic telemetry generator (`app/core/traffic_stream.py`). |
| **Layer 2** | **Normalization** | Regex parsing of raw Apache/Nginx combined headers, IP extraction, status codes, methods, byte sizes (`traffic_manager.parse_raw_access_log`). |
| **Layer 3** | **IP Threat Intelligence** | Autonomous System (ASN) lookup, country/city attribution, Proxy/VPN/Tor node association, and calculated 0-100 risk scoring (`app/core/ip_engine.py`). |
| **Layer 4** | **Detection & Alerting** | Rolling window heuristic rules engine detecting Brute Force attacks, Port Scanning probes, and Bad Bot scrapers with one-click containment (`app/core/detection.py`). |

---

## 🎯 Target Threat Scenarios Implemented (Slide 9)

1. **Automated Brute-Force & Credential Stuffing (`RULE-BF-01`)**:
   - Tracks repeated authentication failures (HTTP 401/403 or rapid POSTs to `/login`, `/wp-login.php`, `/admin`).
   - Triggerable on demand in the **Attack Simulator** tab.
2. **Reconnaissance & Port Scanning Probing (`RULE-SCAN-02`)**:
   - Detects external entities probing sequential or sensitive ports (21, 22, 23, 80, 443, 3306, 3389, 8080).
   - Flagged with HIGH severity and perimeter block recommendation.
3. **Bad Bot & Vulnerability Scraper Filtering (`RULE-BOT-03`)**:
   - Identifies malicious scanner signatures (`sqlmap`, `nikto`, `masscan`, `curl`) and directory traversal exploits (`/.env`, `/wp-config.php`, `/etc/passwd`).

---

## 🧮 NetCalc Pro Subnet & CIDR Module (Slide 7 & Live Prototype)

Integrated directly into the SOC platform (Tab 3: NetCalc Pro Subnet Tool):
- **IPv4 Address validation** and dynamic **CIDR prefix slider (`/0` to `/32`)**
- Instant calculation of:
  - Subnet Mask & Wildcard Mask
  - Network Address & Broadcast Address
  - First Usable IP & Last Usable IP
  - Usable Hosts & Total Host Capacity
  - IPv4 Class (A, B, C, D, E) & Scope (Private / Public / Loopback)
  - Binary Subnet Mask & Binary Network Address
- One-click individual copy buttons and **"Copy All Results"** feature.

---

## ⚡ How to Run the Project Straight Away

### Option 1: Double-Click (Easiest)
Simply double-click the included batch file:
```
start.bat
```
This automatically starts the server and opens `http://127.0.0.1:8080` in your default web browser!

### Option 2: Command Line
Open a terminal in the project directory:
```bash
py run.py
```
Or with uvicorn directly:
```bash
py -m uvicorn app.main:app --host 127.0.0.1 --port 8080
```

---

## 🧪 Testing & Verification Guide

1. **Live Traffic Stream**: Open the dashboard to see live inbound telemetry flowing into the Event Timeline and traffic table.
2. **Slide 6 IP Sample Assessment**: Go to **IP Threat Intelligence**, click the **`198.51.100.42`** button to inspect the sample from the presentation:
   - Network / ASN: `AS13335 (Cloud Provider)`
   - Proxy / Tor: `YES (Public Proxy)`
   - Calculated Risk Score: `78 / 100 (High Risk)`
3. **NetCalc Pro Subnet Calculator**: Go to **NetCalc Pro Subnet Tool**, move the slider or type any IP address to see instant subnet recalculations.
4. **Attack Simulator**: Go to **Attack Simulator**, click **Trigger Brute-Force Attack Wave** or **Trigger Port Scan Wave**, and watch the alert pop up on the screen and in the **Detection & Alerts** tab!
5. **Human-in-the-Loop Containment**: Click **Block IP** on any threat to drop the host in the **Perimeter Firewall** table.
6. **Audit Reports**: Go to **Audit & Reports** to download incident alerts or traffic logs in CSV/JSON format or print the executive summary.
