import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, deque

# Indian Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

class AnomalyDetectionEngine:
    def __init__(self):
        # Rolling window telemetry tracking: {ip: deque([(timestamp, port, status, path, user_agent)])}
        self.ip_history = defaultdict(lambda: deque(maxlen=200))
        self.alerts: List[Dict[str, Any]] = []
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.whitelisted_ips: set = {"127.0.0.1", "::1"}
        
        # Rule counters
        self.detection_stats = {
            "brute_force_detected": 0,
            "port_scans_detected": 0,
            "bad_bots_detected": 0,
            "total_alerts": 0
        }

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluate single log/traffic event against SOC detection rules.
        Returns Alert dict if rule triggered, else None.
        """
        src_ip = event.get("src_ip", "")
        if not src_ip or src_ip in self.whitelisted_ips:
            return None

        # Check if already blocked
        if src_ip in self.blocked_ips:
            event["status_action"] = "BLOCKED_BY_FIREWALL"
            return None

        now = event.get("timestamp", time.time())
        port = event.get("dst_port", 80)
        status = event.get("status_code", 200)
        path = event.get("path", "/")
        user_agent = event.get("user_agent", "")
        method = event.get("method", "GET")

        # Record event in rolling history
        history = self.ip_history[src_ip]
        history.append({
            "time": now,
            "port": port,
            "status": status,
            "path": path,
            "user_agent": user_agent,
            "method": method
        })

        # Prune older than 60 seconds
        cutoff = now - 60
        recent = [e for e in history if e["time"] >= cutoff]

        # ----------------------------------------------------
        # RULE 1: Automated Brute-Force & Credential Stuffing
        # Condition: >= 4 failed auth attempts (status 401/403) or repeated POSTs to login paths within 60s
        # ----------------------------------------------------
        failed_auth_attempts = [e for e in recent if e["status"] in (401, 403) or ("/login" in e["path"] and e["method"] == "POST" and e["status"] != 200)]
        if len(failed_auth_attempts) >= 4:
            alert = self._create_alert(
                rule_id="RULE-BF-01",
                rule_name="Automated Brute-Force / Credential Stuffing",
                severity="CRITICAL",
                src_ip=src_ip,
                details=f"Detected {len(failed_auth_attempts)} repeated authentication failures within 60 seconds targeting '{path}'.",
                category="Authentication Security",
                recommended_action="Block source IP at perimeter firewall and inspect targeted user accounts."
            )
            self.detection_stats["brute_force_detected"] += 1
            return alert

        # ----------------------------------------------------
        # RULE 2: Reconnaissance & Port Scanning Probing
        # Condition: Probing >= 3 distinct sensitive ports within 60s
        # ----------------------------------------------------
        distinct_ports = {e["port"] for e in recent}
        sensitive_ports = {21, 22, 23, 25, 3306, 3389, 5432, 6379, 8080, 8443, 9200}
        probed_sensitive = distinct_ports.intersection(sensitive_ports)
        if len(distinct_ports) >= 3 or len(probed_sensitive) >= 2:
            alert = self._create_alert(
                rule_id="RULE-SCAN-02",
                rule_name="Reconnaissance & Port Scanning Probing",
                severity="HIGH",
                src_ip=src_ip,
                details=f"Sequential port probing observed across {len(distinct_ports)} ports (Targeted: {sorted(list(distinct_ports))}).",
                category="Network Reconnaissance",
                recommended_action="Drop ingress packets on edge router and blacklist source CIDR range."
            )
            self.detection_stats["port_scans_detected"] += 1
            return alert

        # ----------------------------------------------------
        # RULE 3: Bad Bot & Vulnerability Scraper Filtering
        # Condition: Known vulnerability scanners (sqlmap, nikto, masscan, dirbuster) or exploit path traversal
        # ----------------------------------------------------
        ua_lower = user_agent.lower()
        path_lower = path.lower()
        bad_bot_patterns = ["sqlmap", "nikto", "masscan", "zgrab", "dirbuster", "nmap", "gobuster", "curl/"]
        exploit_paths = ["wp-config", ".env", "phpinfo", "etc/passwd", "../", "cgi-bin", "actuator/health", ".git/config"]

        matched_pattern = next((p for p in bad_bot_patterns if p in ua_lower), None)
        matched_exploit = next((p for p in exploit_paths if p in path_lower), None)

        if matched_pattern or matched_exploit:
            threat_detail = f"Identified malicious tool '{matched_pattern}' in User-Agent." if matched_pattern else f"Exploit path traversal probe targeting '{matched_exploit}'."
            alert = self._create_alert(
                rule_id="RULE-BOT-03",
                rule_name="Malicious Bot / Vulnerability Scraper",
                severity="HIGH",
                src_ip=src_ip,
                details=threat_detail,
                category="Application Layer Attack",
                recommended_action="Enforce bot protection challenge / WAF signature block on URI."
            )
            self.detection_stats["bad_bots_detected"] += 1
            return alert

        return None

    def _create_alert(self, rule_id: str, rule_name: str, severity: str, src_ip: str, details: str, category: str, recommended_action: str) -> Dict[str, Any]:
        alert_id = f"ALT-{int(time.time()*1000)%1000000}"
        alert = {
            "id": alert_id,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "src_ip": src_ip,
            "category": category,
            "details": details,
            "timestamp": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST"),
            "status": "ACTIVE_INVESTIGATION",
            "recommended_action": recommended_action
        }
        self.alerts.insert(0, alert)
        if len(self.alerts) > 100:
            self.alerts.pop()
        self.detection_stats["total_alerts"] += 1
        return alert

    def block_ip(self, ip_str: str, reason: str, analyst: str = "SOC Analyst") -> Dict[str, Any]:
        entry = {
            "ip": ip_str,
            "reason": reason,
            "analyst": analyst,
            "blocked_at": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST"),
            "action": "DROP_ALL_INBOUND"
        }
        self.blocked_ips[ip_str] = entry
        return entry

    def unblock_ip(self, ip_str: str) -> bool:
        if ip_str in self.blocked_ips:
            del self.blocked_ips[ip_str]
            return True
        return False

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.alerts[:limit]

    def get_blocked_list(self) -> List[Dict[str, Any]]:
        return list(self.blocked_ips.values())

    def investigate_incident(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Executes the Slide 9 Incident Investigation & Triage Workflow.
        Answers key triage question: 'Did any attempt succeed?'
        """
        alert = next((a for a in self.alerts if a["id"] == alert_id), None)
        if not alert:
            return None

        src_ip = alert["src_ip"]
        history = list(self.ip_history.get(src_ip, []))

        # Check for any successful logon (status 200 on login path or successful authenticated access)
        successful_logons = [
            e for e in history 
            if e["status"] == 200 and ("/login" in e["path"] or "/admin" in e["path"] or "/auth" in e["path"])
        ]
        attempt_succeeded = len(successful_logons) > 0

        if attempt_succeeded:
            triage_verdict = "CRITICAL: ACCOUNT COMPROMISE DETECTED"
            action_branch = "Successful logon found - account compromised"
            remediation_steps = [
                "1. Immediately disable compromised user account in identity provider / Active Directory.",
                "2. Force global session termination and mandatory password reset.",
                "3. Quarantine source IP at perimeter firewall.",
                "4. Escalate to Tier-2 Incident Response for lateral movement analysis."
            ]
        else:
            triage_verdict = "DEFENDED: NO SUCCESSFUL LOGON DETECTED"
            action_branch = "No successful logon detected"
            remediation_steps = [
                "1. Block offending source IP at perimeter firewall.",
                "2. Add source IP to SOC watchlist and Threat Intelligence sharing feed.",
                "3. Review targeted accounts for weak passwords or repeated lockouts.",
                "4. Monitor edge logs for resumed attempts from related subnets."
            ]

        return {
            "alert": alert,
            "src_ip": src_ip,
            "total_probes_recorded": len(history),
            "key_triage_question": "Did any attempt succeed?",
            "attempt_succeeded": attempt_succeeded,
            "action_branch": action_branch,
            "triage_verdict": triage_verdict,
            "remediation_steps": remediation_steps,
            "recent_events": history[-10:]
        }

detection_engine = AnomalyDetectionEngine()
