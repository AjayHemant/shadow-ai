"""
SentinelGate - Interceptor
Acts as the local HTTPS proxy / traffic interceptor.
Runs as a lightweight HTTP server that applications send data through.
Inspects payloads, runs the detection + policy pipeline, and returns a decision.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
from detection_engine import DetectionEngine
from policy_engine import PolicyEngine
from alert_logger import log_alert

detection_engine = DetectionEngine()
policy_engine = PolicyEngine()

INTERCEPT_HOST = "0.0.0.0"
INTERCEPT_PORT = 8080


class InterceptHandler(BaseHTTPRequestHandler):
    """
    Receives POST /inspect requests with JSON body:
    {
        "payload": "...",
        "source_app": "...",
        "destination": "..."
    }
    Returns JSON:
    {
        "action": "BLOCK|WARN|ALLOW",
        "reason": "...",
        "detections": [...],
        "triggered_rules": [...]
    }
    """

    def log_message(self, format, *args):
        # Suppress default HTTP logs, dashboard handles display
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/inspect":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                self._send_json({"error": "Invalid JSON"}, 400)
                return

            payload = body.get("payload", "")
            source_app = body.get("source_app", "Unknown")
            destination = body.get("destination", "Unknown")

            scan_result = detection_engine.scan(payload)
            decision = policy_engine.evaluate(scan_result, destination)

            # Log every event to the DB
            log_alert(
                source_app=source_app,
                destination=destination,
                action=decision.action,
                highest_severity=scan_result.highest_severity,
                detections=scan_result.detections,
                payload=payload,
                triggered_rules=decision.triggered_rules,
            )

            response = {
                "action": decision.action,
                "reason": decision.reason,
                "triggered_rules": decision.triggered_rules,
                "detections": [
                    {
                        "data_type": d.data_type,
                        "redacted_value": d.redacted_value,
                        "severity": d.severity,
                        "description": d.description,
                    }
                    for d in scan_result.detections
                ],
            }

            status_code = 200
            if decision.action == "BLOCK":
                status_code = 403
            elif decision.action == "WARN":
                status_code = 200

            self._send_json(response, status_code)

        elif path == "/clear":
            from alert_logger import clear_alerts
            clear_alerts()
            self._send_json({"status": "cleared"})

        else:
            self._send_json({"error": "Not found"}, 404)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/alerts":
            from alert_logger import get_recent_alerts
            alerts = get_recent_alerts(100)
            self._send_json(alerts)

        elif path == "/stats":
            from alert_logger import get_stats
            stats = get_stats()
            self._send_json(stats)

        elif path == "/health":
            self._send_json({"status": "ok", "service": "SentinelGate Interceptor"})

        else:
            self._send_json({"error": "Not found"}, 404)


def run_interceptor():
    server = HTTPServer((INTERCEPT_HOST, INTERCEPT_PORT), InterceptHandler)
    print(f"[SentinelGate] Interceptor listening on {INTERCEPT_HOST}:{INTERCEPT_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run_interceptor()
