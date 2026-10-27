import uvicorn
import webbrowser
import threading
import time
import sys

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://127.0.0.1:8080")

if __name__ == "__main__":
    print("=" * 70)
    print("  RoutePulse SOC — Real-Time Network Traffic Monitoring & IP Threat Assessment")
    print("  Capstone Project Phase I & IBM Mentorship Implementation")
    print("  Server launching on: http://127.0.0.1:8080")
    print("=" * 70)
    
    # Launch browser automatically
    threading.Thread(target=open_browser, daemon=True).start()

    # Start FastAPI server
    try:
        uvicorn.run("app.main:app", host="127.0.0.1", port=8080, log_level="info")
    except KeyboardInterrupt:
        print("\n[!] RoutePulse SOC shut down successfully.")
        sys.exit(0)
