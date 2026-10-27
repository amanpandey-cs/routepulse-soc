import io
import csv
import json
import time
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from app.config import STATIC_DIR, APP_TITLE, VERSION
from app.core.subnet_calc import calculate_subnet, check_ip_in_subnet
from app.core.ip_engine import ip_threat_engine
from app.core.detection import detection_engine
from app.core.traffic_stream import traffic_manager

app = FastAPI(title=APP_TITLE, version=VERSION)

# Mount static folder
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Request Models
class SubnetRequest(BaseModel):
    ip: str
    prefix: int

class CheckSubnetMemberRequest(BaseModel):
    candidate_ip: str
    network_cidr: str

class WebhookTestRequest(BaseModel):
    webhook_url: Optional[str] = None
    alert_id: Optional[str] = None

class BlockIPRequest(BaseModel):
    ip: str
    reason: str
    analyst: Optional[str] = "SOC Analyst"

class UnblockIPRequest(BaseModel):
    ip: str

class SimulateScenarioRequest(BaseModel):
    scenario: str  # brute_force, port_scan, bad_bot, normal

@app.get("/", response_class=HTMLResponse)
async def serve_root():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>RoutePulse SOC Platform Ready.</h1>"

# ---------------------------------------------------------
# Subnet & CIDR NetCalc Pro APIs
# ---------------------------------------------------------
@app.post("/api/v1/subnet/calculate")
async def api_calculate_subnet(req: SubnetRequest):
    try:
        results = calculate_subnet(req.ip, req.prefix)
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/subnet/calculate")
async def api_calculate_subnet_get(ip: str = "192.168.1.1", prefix: int = 24):
    try:
        results = calculate_subnet(ip, prefix)
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/v1/subnet/check-member")
async def api_check_subnet_member(req: CheckSubnetMemberRequest):
    try:
        result = check_ip_in_subnet(req.candidate_ip, req.network_cidr)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ---------------------------------------------------------
# IP Threat Assessment & Intelligence APIs
# ---------------------------------------------------------
@app.get("/api/v1/ip/assess")
async def api_assess_ip(ip: str = Query(..., description="Target IPv4 or IPv6 address")):
    assessment = ip_threat_engine.assess_ip(ip)
    return {"status": "success", "data": assessment}

# ---------------------------------------------------------
# Real-Time Traffic & Telemetry APIs
# ---------------------------------------------------------
@app.get("/api/v1/traffic/events")
async def api_get_traffic_events(limit: int = 50):
    events = traffic_manager.get_recent_events(limit=limit)
    return {"status": "success", "count": len(events), "events": events}

@app.get("/api/v1/traffic/metrics")
async def api_get_traffic_metrics():
    metrics = traffic_manager.get_metrics()
    return {"status": "success", "metrics": metrics}

@app.post("/api/v1/traffic/generate")
async def api_generate_traffic_event(req: Optional[SimulateScenarioRequest] = None):
    scenario = req.scenario if req else None
    evt = traffic_manager.generate_event(forced_scenario=scenario)
    return {"status": "success", "event": evt}

@app.post("/api/v1/traffic/upload-logs")
async def api_upload_logs(file: Optional[UploadFile] = File(None), raw_log_text: Optional[str] = Form(None)):
    content = ""
    if file:
        content_bytes = await file.read()
        content = content_bytes.decode("utf-8", errors="ignore")
    elif raw_log_text:
        content = raw_log_text
    else:
        raise HTTPException(status_code=400, detail="No log file or text provided")

    parsed = traffic_manager.parse_raw_access_log(content)
    return {
        "status": "success",
        "ingested_count": len(parsed),
        "alerts_triggered": len([p for p in parsed if "triggered_alert" in p]),
        "events": parsed
    }

# ---------------------------------------------------------
# SOC Alerting & Incident APIs
# ---------------------------------------------------------
@app.get("/api/v1/alerts")
async def api_get_alerts(limit: int = 50):
    alerts = detection_engine.get_alerts(limit=limit)
    return {"status": "success", "count": len(alerts), "alerts": alerts}

@app.post("/api/v1/alerts/dismiss")
async def api_dismiss_alert(alert_id: str = Form(...)):
    detection_engine.alerts = [a for a in detection_engine.alerts if a.get("id") != alert_id]
    return {"status": "success", "message": f"Alert {alert_id} dismissed"}

@app.get("/api/v1/alerts/investigate")
async def api_investigate_alert(alert_id: str = Query(...)):
    investigation = detection_engine.investigate_incident(alert_id)
    if not investigation:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return {"status": "success", "investigation": investigation}

@app.post("/api/v1/webhooks/test-dispatch")
async def api_test_webhook(req: WebhookTestRequest):
    # Simulated webhook dispatcher for SIEM / SOAR / Slack integrations
    alert = next((a for a in detection_engine.alerts if a["id"] == req.alert_id), None) if req.alert_id else (detection_engine.alerts[0] if detection_engine.alerts else None)
    
    payload = {
        "event_type": "SECURITY_INCIDENT_ALERT",
        "timestamp": time.time(),
        "source": "RoutePulse SOC v5.0.87",
        "severity": alert["severity"] if alert else "HIGH",
        "rule_name": alert["rule_name"] if alert else "Perimeter Intrusion Detection",
        "src_ip": alert["src_ip"] if alert else "198.51.100.42",
        "details": alert["details"] if alert else "Simulated SOAR webhook notification payload.",
        "recommended_action": alert["recommended_action"] if alert else "Drop at perimeter firewall."
    }

    # If user provided a real webhook URL, attempt post
    dispatched = False
    status_msg = "Simulated webhook payload generated successfully."
    if req.webhook_url and req.webhook_url.startswith("http"):
        try:
            import requests
            r = requests.post(req.webhook_url, json=payload, timeout=2.0)
            dispatched = True
            status_msg = f"Webhook successfully posted to external URL (HTTP {r.status_code})"
        except Exception as e:
            status_msg = f"External webhook post failed: {e}"

    return {
        "status": "success",
        "dispatched": dispatched,
        "message": status_msg,
        "payload": payload
    }

# ---------------------------------------------------------
# Firewall & Perimeter Control APIs
# ---------------------------------------------------------
@app.get("/api/v1/firewall/blocked")
async def api_get_blocked():
    blocked = detection_engine.get_blocked_list()
    return {"status": "success", "count": len(blocked), "blocked_ips": blocked}

@app.post("/api/v1/firewall/block")
async def api_block_ip(req: BlockIPRequest):
    entry = detection_engine.block_ip(req.ip, req.reason, req.analyst or "SOC Analyst")
    return {"status": "success", "message": f"IP {req.ip} dropped at firewall", "entry": entry}

@app.post("/api/v1/firewall/unblock")
async def api_unblock_ip(req: UnblockIPRequest):
    success = detection_engine.unblock_ip(req.ip)
    return {"status": "success" if success else "not_found", "unblocked": success}

# ---------------------------------------------------------
# Export & Reporting APIs (CSV, JSON)
# ---------------------------------------------------------
@app.get("/api/v1/reports/export")
async def api_export_report(format: str = "json", export_type: str = "alerts"):
    if export_type == "alerts":
        data = detection_engine.get_alerts(100)
    else:
        data = traffic_manager.get_recent_events(100)

    if format == "csv":
        output = io.StringIO()
        if data:
            keys = list(data[0].keys())
            writer = csv.DictWriter(output, fieldnames=keys)
            writer.writeheader()
            for row in data:
                # simplify nested dicts for csv
                cleaned = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in row.items()}
                writer.writerow(cleaned)
        csv_str = output.getvalue()
        return Response(content=csv_str, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=soc_{export_type}_report.csv"})

    return JSONResponse(content={"export_type": export_type, "timestamp": time.time(), "records": data})
