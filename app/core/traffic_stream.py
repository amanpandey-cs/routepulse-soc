import time
import random
import re
from typing import List, Dict, Any, Optional
from collections import deque
from app.core.detection import detection_engine
from app.core.ip_engine import ip_threat_engine

# Common web user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/7.88.1",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6"
]

NORMAL_PATHS = [
    "/", "/index.html", "/api/v1/status", "/assets/app.css", "/assets/app.js",
    "/dashboard", "/pricing", "/products/catalog", "/contact", "/search?q=security"
]

AUTH_PATHS = [
    "/api/auth/login", "/admin/login.php", "/wp-login.php", "/oauth/token", "/auth/verify"
]

EXPLOIT_PATHS = [
    "/.env", "/wp-config.php.bak", "/etc/passwd", "/cgi-bin/test.cgi",
    "/actuator/health", "/phpinfo.php", "/.git/config"
]

PROBED_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]

SIMULATED_IPS = [
    # Clean IPs
    "142.250.190.46", "13.107.42.16", "151.101.1.69", "104.244.42.1", "172.217.16.206",
    # Known threat/suspicious IPs
    "198.51.100.42", "185.220.101.5", "45.155.205.233", "194.26.29.112", "91.240.118.172",
    # Internal / RFC 1918
    "192.168.1.105", "10.0.4.15"
]

class TrafficStreamManager:
    def __init__(self):
        self.events_buffer = deque(maxlen=500)
        self.is_streaming = True
        self.stream_interval_sec = 1.0
        self.total_events_processed = 0
        self.total_bytes_transferred = 0
        self.status_counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
        self.protocol_counts = {"TCP/HTTP": 0, "TLS/HTTPS": 0, "UDP/DNS": 0}

    def generate_event(self, forced_scenario: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a single telemetry packet representing inbound network traffic.
        Supports forced scenarios: 'brute_force', 'port_scan', 'bad_bot'.
        """
        now = time.time()
        
        if forced_scenario == "brute_force":
            src_ip = "45.155.205.233"
            dst_port = 443
            method = "POST"
            path = random.choice(AUTH_PATHS)
            status_code = random.choice([401, 403, 429])
            proto = "TLS/HTTPS"
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
            bytes_sent = random.randint(240, 520)
        elif forced_scenario == "port_scan":
            src_ip = "185.220.101.5"
            dst_port = random.choice(PROBED_PORTS)
            method = "GET"
            path = "/"
            status_code = random.choice([404, 502, 400])
            proto = "TCP/HTTP"
            ua = "masscan/1.3.2"
            bytes_sent = random.randint(64, 180)
        elif forced_scenario == "bad_bot":
            src_ip = "198.51.100.42"
            dst_port = 80
            method = "GET"
            path = random.choice(EXPLOIT_PATHS)
            status_code = 404
            proto = "TCP/HTTP"
            ua = random.choice(["sqlmap/1.7.2#stable", "Nikto/2.1.6", "curl/7.88.1"])
            bytes_sent = random.randint(120, 360)
        else:
            # Normal distribution with 15% random anomaly injection
            roll = random.random()
            if roll < 0.10:
                # Occasional suspicious bot or login failure
                src_ip = random.choice(["198.51.100.42", "45.155.205.233"])
                dst_port = random.choice([80, 443, 8080])
                method = random.choice(["POST", "GET"])
                path = random.choice(AUTH_PATHS + EXPLOIT_PATHS)
                status_code = random.choice([401, 403, 404])
                proto = "TLS/HTTPS" if dst_port == 443 else "TCP/HTTP"
                ua = random.choice(USER_AGENTS)
                bytes_sent = random.randint(300, 1200)
            else:
                # Regular user traffic
                src_ip = random.choice(SIMULATED_IPS)
                dst_port = random.choice([80, 443])
                method = random.choice(["GET", "GET", "GET", "POST"])
                path = random.choice(NORMAL_PATHS)
                status_code = random.choice([200, 200, 200, 204, 301, 304])
                proto = "TLS/HTTPS" if dst_port == 443 else "TCP/HTTP"
                ua = random.choice(USER_AGENTS[:4])
                bytes_sent = random.randint(1400, 84000)

        latency_ms = round(random.uniform(8.5, 92.0), 1)

        event = {
            "id": f"EVT-{int(now * 1000) % 10000000}",
            "timestamp": now,
            "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
            "src_ip": src_ip,
            "dst_ip": "172.31.24.10",
            "dst_port": dst_port,
            "protocol": proto,
            "method": method,
            "path": path,
            "status_code": status_code,
            "bytes_transferred": bytes_sent,
            "latency_ms": latency_ms,
            "user_agent": ua,
            "status_action": "PERMITTED"
        }

        # Ingestion & Detection processing
        self._record_event(event)
        alert = detection_engine.process_event(event)
        if alert:
            event["triggered_alert"] = alert

        return event

    def _record_event(self, event: Dict[str, Any]):
        self.events_buffer.appendleft(event)
        self.total_events_processed += 1
        self.total_bytes_transferred += event.get("bytes_transferred", 0)

        # Update status code telemetry
        sc = event.get("status_code", 200)
        if 200 <= sc < 300:
            self.status_counts["2xx"] += 1
        elif 300 <= sc < 400:
            self.status_counts["3xx"] += 1
        elif 400 <= sc < 500:
            self.status_counts["4xx"] += 1
        elif sc >= 500:
            self.status_counts["5xx"] += 1

        proto = event.get("protocol", "TCP/HTTP")
        if proto in self.protocol_counts:
            self.protocol_counts[proto] += 1
        else:
            self.protocol_counts["TCP/HTTP"] += 1

    def parse_raw_access_log(self, raw_text: str) -> List[Dict[str, Any]]:
        """
        Layer 2: Normalization & parsing of raw Apache/Nginx combined log lines.
        Format: IP - - [date] "METHOD PATH PROTO" status bytes "ref" "UA"
        """
        pattern = re.compile(
            r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
        )
        parsed_events = []
        for line in raw_text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(line)
            if m:
                data = m.groupdict()
                src_ip = data["ip"]
                status = int(data["status"])
                bytes_sent = int(data["bytes"]) if data["bytes"].isdigit() else 256
                method = data["method"]
                path = data["path"]
                ua = data["ua"] or "Generic Agent"

                event = {
                    "id": f"LOG-{int(time.time()*1000)%10000000}",
                    "timestamp": time.time(),
                    "time_str": time.strftime("%H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": "172.31.24.10",
                    "dst_port": 80 if "http:" in path.lower() else 443,
                    "protocol": "TLS/HTTPS" if status == 443 else "TCP/HTTP",
                    "method": method,
                    "path": path,
                    "status_code": status,
                    "bytes_transferred": bytes_sent,
                    "latency_ms": 24.0,
                    "user_agent": ua,
                    "status_action": "PERMITTED"
                }
                self._record_event(event)
                alert = detection_engine.process_event(event)
                if alert:
                    event["triggered_alert"] = alert
                parsed_events.append(event)
        return parsed_events

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return list(self.events_buffer)[:limit]

    def get_metrics(self) -> Dict[str, Any]:
        """Aggregate telemetry metrics for dashboard KPI cards"""
        # Active threat IPs
        active_threat_ips = set()
        for alert in detection_engine.alerts:
            active_threat_ips.add(alert.get("src_ip"))

        # Calculate high-risk hosts
        blocked_count = len(detection_engine.blocked_ips)
        total_alerts = detection_engine.detection_stats["total_alerts"]
        
        # Threat Level estimation
        if len(detection_engine.alerts) > 5 or blocked_count > 3:
            threat_gauge = "ELEVATED"
            gauge_val = 72
        elif len(detection_engine.alerts) > 1:
            threat_gauge = "MODERATE"
            gauge_val = 45
        else:
            threat_gauge = "GUARDED / SAFE"
            gauge_val = 18

        return {
            "total_scans": self.total_events_processed,
            "events_24h": 440200 + self.total_events_processed,
            "threat_ips": len(active_threat_ips) + 3,
            "feed_matches": 108700 + len(detection_engine.alerts),
            "loaded_indicators": 356683,
            "feeds_ok": "30/30",
            "tuning_rules": 197,
            "hosts_scored": 19600 + self.total_events_processed,
            "blocked_hosts": blocked_count,
            "threat_gauge": threat_gauge,
            "threat_gauge_percent": gauge_val,
            "status_counts": self.status_counts,
            "protocol_counts": self.protocol_counts,
            "detection_stats": detection_engine.detection_stats
        }

traffic_manager = TrafficStreamManager()

# Pre-populate buffer with initial realistic telemetry
for _ in range(25):
    traffic_manager.generate_event()
