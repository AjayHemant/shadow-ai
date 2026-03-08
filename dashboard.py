"""
SentinelGate - Dashboard Backend (Flask)
Serves the monitoring dashboard and proxies API calls to the interceptor.
Now also provides proxy management endpoints for the system-wide proxy.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, request, send_from_directory, make_response, render_template
from alert_logger import get_recent_alerts, get_stats, clear_alerts, get_running_apps, log_running_apps
import sentinel_engine_cpp
import socket
import threading
import time

# --- Server Configuration ---
# Binding to localhost (127.0.0.1) prevents external network access.
# This ensures that only processes running on this specific machine can 
# access the dashboard and APIs, mitigating remote unauthorized access and DoS.
HOST = "127.0.0.1" 
PORT = 5000
DEBUG = False
# ----------------------------

app = Flask(__name__, static_folder="static", template_folder="templates")

# Ensure CWD is the script directory so C++ engine can find rules.json
app_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(app_dir)

if not os.path.exists("rules.json"):
    print(f"[SentinelGate] CRITICAL: rules.json not found in {app_dir}!")
else:
    print(f"[SentinelGate] Found rules.json in {app_dir}")

# Initialize the blazing fast C++ pipeline
dlp_engine = sentinel_engine_cpp.SentinelEngine()


def _cors(response):
    """Add CORS headers so browser extensions can call the API."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.after_request
def after_request(response):
    return _cors(response)


@app.route("/", methods=["GET"])
def index():
    return send_from_directory("templates", "dashboard.html")





# ── Handle OPTIONS preflight for all /api/* routes ──
@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return make_response("", 204)


@app.route("/image-test")
def image_test():
    """Serves the interactive image OCR test page."""
    return render_template("image_test.html")

@app.route("/file-test")
def file_test():
    """Serves the interactive file scan test page."""
    return render_template("file_test.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = get_recent_alerts(100)
    return jsonify(alerts)


@app.route("/api/stats")
def api_stats():
    stats = get_stats()
    return jsonify(stats)


@app.route("/api/clear", methods=["POST"])
def api_clear():
    clear_alerts()
    return jsonify({"status": "cleared"})


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Scan a payload through the full DLP pipeline. Called by the browser extension."""
    body = request.get_json(force=True)
    payload     = body.get("payload", "")
    source_app  = body.get("source_app", "Simulator")
    destination = body.get("destination", "api.external.com")

    # Call the native C++ engine (blazing fast)
    scan_result, decision = dlp_engine.process_payload(payload, destination)

    # Get system and network context
    sender_ip = request.remote_addr
    try:
        user_system_name = os.getlogin()
    except Exception:
        user_system_name = os.getenv("USERNAME", os.getenv("USER", "Unknown"))

    from alert_logger import log_alert
    log_alert(
        sender_ip=sender_ip,
        user_system_name=user_system_name,
        source_app=source_app,
        destination=destination,
        action=decision.action,
        highest_severity=scan_result.highest_severity,
        detections=scan_result.detections,
        payload=payload,
        triggered_rules=decision.triggered_rules,
    )

    return jsonify({
        "action":          decision.action,
        "reason":          decision.reason,
        "triggered_rules": decision.triggered_rules,
        "detections": [
            {
                "data_type":     d.data_type,
                "redacted_value": d.redacted_value,
                "severity":      d.severity,
                "description":   d.description,
            }
            for d in scan_result.detections
        ],
    })


@app.route("/api/simulate/file", methods=["POST"])
def api_simulate_file():
    """Extracts text from uploaded files (.txt, .doc, .docx, .pdf) and scans for sensitive data."""
    import base64
    import io

    body = request.get_json(force=True)
    b64_file = body.get("file_data", "")
    filename = body.get("filename", "unknown.txt")
    source_app = body.get("source_app", "SentinelGate Browser")
    destination = body.get("destination", "api.external.com")

    # Remove data URL header if present
    if "base64," in b64_file:
        b64_file = b64_file.split("base64,")[1]

    try:
        file_bytes = base64.b64decode(b64_file)
    except Exception as e:
        print(f"[SentinelGate] Invalid base64 file data: {e}")
        return jsonify({"action": "ALLOW", "reason": "Invalid file data.", "detections": []})

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    extracted_text = ""

    print(f"[SentinelGate] Scanning file: {filename} ({len(file_bytes)} bytes, type: .{ext})")

    # ── TEXT EXTRACTION ──
    try:
        if ext == "txt":
            extracted_text = file_bytes.decode("utf-8", errors="ignore")

        elif ext == "pdf":
            from PyPDF2 import PdfReader
            reader = PdfReader(io.BytesIO(file_bytes))
            pages = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    pages.append(text)
            extracted_text = "\n".join(pages)

        elif ext == "docx":
            from docx import Document
            doc = Document(io.BytesIO(file_bytes))
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
            extracted_text = "\n".join(paragraphs)

        elif ext == "doc":
            # .doc is a legacy binary format. Try reading as raw text extraction.
            extracted_text = file_bytes.decode("utf-8", errors="ignore")
            # Filter out binary noise — keep only printable ASCII lines
            import re
            lines = extracted_text.split("\n")
            clean_lines = [l for l in lines if len(l.strip()) > 3 and re.search(r'[a-zA-Z]{3,}', l)]
            extracted_text = "\n".join(clean_lines)

        else:
            return jsonify({"action": "ALLOW", "reason": f"Unsupported file type: .{ext}", "detections": []})

    except Exception as e:
        print(f"[SentinelGate] File text extraction failed: {e}")
        return jsonify({"action": "ALLOW", "reason": f"Could not read file: {e}", "detections": []})

    if not extracted_text.strip():
        return jsonify({"action": "ALLOW", "reason": "No text content found in file.", "detections": []})

    print(f"[SentinelGate] Extracted {len(extracted_text)} chars from {filename}")

    # ── Run through the C++ DLP Engine ──
    scan_result, decision = dlp_engine.process_payload(extracted_text, destination)

    sender_ip = request.remote_addr
    try:
        user_system_name = os.getlogin()
    except Exception:
        user_system_name = os.getenv("USERNAME", os.getenv("USER", "Unknown"))

    if scan_result.is_sensitive:
        from alert_logger import log_alert
        log_alert(
            sender_ip=sender_ip,
            user_system_name=user_system_name,
            source_app=source_app,
            destination=destination,
            action=decision.action,
            highest_severity=scan_result.highest_severity,
            detections=scan_result.detections,
            payload=f"[FILE: {filename}]\n" + extracted_text[:500],
            triggered_rules=decision.triggered_rules,
        )

    return jsonify({
        "action":          decision.action,
        "reason":          decision.reason,
        "triggered_rules": decision.triggered_rules,
        "filename":        filename,
        "detections": [
            {
                "data_type":     d.data_type,
                "redacted_value": d.redacted_value,
                "severity":      d.severity,
                "description":   d.description,
            }
            for d in scan_result.detections
        ],
    })


# ── Proxy Management Endpoints ──

@app.route("/api/proxy/status")
def api_proxy_status():
    """Get the current system proxy status."""
    try:
        from proxy_manager import is_proxy_active, get_current_proxy_settings, PROXY_HOST, PROXY_PORT
        settings = get_current_proxy_settings()
        active = is_proxy_active()
        return jsonify({
            "proxy_active": active,
            "proxy_enabled": settings["enabled"],
            "proxy_server": settings["server"],
            "proxy_bypass": settings["override"],
            "sentinelgate_proxy": f"{PROXY_HOST}:{PROXY_PORT}",
            "mode": "system-wide" if active else "extension-only",
        })
    except Exception as e:
        return jsonify({
            "proxy_active": False,
            "error": str(e),
            "mode": "unknown",
        })


@app.route("/api/proxy/enable", methods=["POST"])
def api_proxy_enable():
    """Enable the system-wide proxy."""
    try:
        from proxy_manager import enable_system_proxy
        success = enable_system_proxy()
        return jsonify({"success": success, "action": "enabled"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/proxy/disable", methods=["POST"])
def api_proxy_disable():
    """Disable the system-wide proxy."""
    try:
        from proxy_manager import disable_system_proxy
        success = disable_system_proxy()
        return jsonify({"success": success, "action": "disabled"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── App Monitor Endpoints ──

@app.route("/api/apps")
def api_apps():
    """Get currently running monitored apps (live scan)."""
    try:
        apps = get_running_apps()
        return jsonify({
            "apps": apps,
            "total": len(apps),
            "scannable": sum(1 for a in apps if a["scannable"]),
            "unscannable": sum(1 for a in apps if not a["scannable"]),
        })
    except Exception as e:
        return jsonify({"apps": [], "error": str(e)})


# ── Background App Monitor Thread ──
def _app_monitor_loop():
    """Periodically scan running apps and log to DB."""
    while True:
        try:
            log_running_apps()
        except Exception as e:
            print(f"[AppMonitor] Error: {e}")
        time.sleep(30)  # Scan every 30 seconds

_monitor_thread = threading.Thread(target=_app_monitor_loop, daemon=True)
_monitor_thread.start()


if __name__ == "__main__":
    print(f"[SentinelGate] Dashboard running at http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=DEBUG)
