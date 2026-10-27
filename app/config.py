import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "app" / "static"
LOGS_DIR = BASE_DIR / "logs"

PORT = int(os.getenv("PORT", 8080))
HOST = os.getenv("HOST", "127.0.0.1")

APP_TITLE = "RoutePulse SOC — Real-Time Network Traffic Monitoring & IP Threat Assessment"
VERSION = "5.0.87-SOC"
