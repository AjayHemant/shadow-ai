"""
SentinelGate - MITM Proxy Addon for mitmproxy
Intercepts ALL outgoing HTTP/HTTPS traffic at the OS level,
scans request bodies through the C++ DLP engine, and blocks
requests containing sensitive data.

This replaces the need for a browser extension — it works with
every app on the system (browsers, desktop apps, etc.)
"""

import os
import sys
import json
import logging
from datetime import datetime

# Add the sentinelgate directory to the path so we can import our modules
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from mitmproxy import http, ctx
from mitmproxy.net.http.http1.assemble import assemble_response

# Import our engines
try:
    import sentinel_engine_cpp
    dlp_engine = sentinel_engine_cpp.SentinelEngine()
    ENGINE_TYPE = "C++ (Native)"
except ImportError:
    from detection_engine import DetectionEngine
    from policy_engine import PolicyEngine
    dlp_engine = None
    py_detection = DetectionEngine()
    py_policy = PolicyEngine()
    ENGINE_TYPE = "Python (Fallback)"

from alert_logger import log_alert

# ─── Configuration ───────────────────────────────────────────────────────────
# Minimum request body size to scan (skip tiny requests for performance)
MIN_SCAN_SIZE = 8

# Domains to NEVER intercept (allow passthrough without scanning)
PASSTHROUGH_DOMAINS = {
    # SentinelGate itself
    "127.0.0.1",
    "localhost",
    # Authentication & Login (NEVER intercept login flows)
    "accounts.google.com",
    "accounts.youtube.com",
    "login.microsoftonline.com",
    "login.live.com",
    "login.microsoft.com",
    "login.yahoo.com",
    "appleid.apple.com",
    "idmsa.apple.com",
    "github.com",
    "gitlab.com",
    "auth0.com",
    "login.salesforce.com",
    "sso.godaddy.com",
    "signin.aws.amazon.com",
    # Password Managers
    "vault.bitwarden.com",
    "my.1password.com",
    "lastpass.com",
    # OS/System
    "windowsupdate.com",
    "update.microsoft.com",
    "download.windowsupdate.com",
    "ctldl.windowsupdate.com",
    "settings-win.data.microsoft.com",
    # Certificate / OCSP
    "ocsp.digicert.com",
    "ocsp.pki.goog",
    "crl.microsoft.com",
    "crl3.digicert.com",
}

# Content types to scan (text-based payloads only)
SCANNABLE_CONTENT_TYPES = {
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/html",
    "application/xml",
    "text/xml",
    "application/graphql",
    "multipart/form-data",
}

# HTML block page served to browsers when a request is blocked
BLOCK_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SentinelGate — Request Blocked</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: #08090d;
            color: #e8eaf0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #0f1117;
            border: 1px solid #1e2230;
            border-radius: 16px;
            padding: 48px;
            max-width: 540px;
            text-align: center;
            box-shadow: 0 8px 48px rgba(255, 77, 109, 0.1);
        }
        .shield { font-size: 64px; margin-bottom: 16px; }
        h1 {
            font-size: 24px;
            font-weight: 800;
            color: #ff4d6d;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #7a8299;
            font-size: 14px;
            margin-bottom: 24px;
            line-height: 1.6;
        }
        .details {
            background: #171923;
            border: 1px solid #252a3a;
            border-radius: 8px;
            padding: 16px;
            text-align: left;
            font-size: 13px;
            margin-bottom: 20px;
        }
        .details .row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #1e2230;
        }
        .details .row:last-child { border-bottom: none; }
        .label { color: #7a8299; }
        .value { color: #e8eaf0; font-weight: 600; }
        .value.blocked { color: #ff4d6d; }
        .detection-list {
            margin-top: 12px;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            justify-content: center;
        }
        .det-badge {
            background: rgba(255, 77, 109, 0.12);
            color: #ff4d6d;
            border: 1px solid rgba(255, 77, 109, 0.3);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
        }
        .footer {
            color: #4a5168;
            font-size: 11px;
            margin-top: 16px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="shield">🛡️</div>
        <h1>Request Blocked</h1>
        <p class="subtitle">
            SentinelGate detected sensitive data in this outgoing request
            and blocked it to prevent a data leak.
        </p>
        <div class="details">
            <div class="row">
                <span class="label">Destination</span>
                <span class="value">{destination}</span>
            </div>
            <div class="row">
                <span class="label">Source App</span>
                <span class="value">{source_app}</span>
            </div>
            <div class="row">
                <span class="label">Action</span>
                <span class="value blocked">⛔ BLOCKED</span>
            </div>
            <div class="row">
                <span class="label">Reason</span>
                <span class="value">{reason}</span>
            </div>
        </div>
        <div class="detection-list">
            {detection_badges}
        </div>
        <p class="footer">
            SentinelGate Pre-Network DLP • {timestamp}
        </p>
    </div>
</body>
</html>"""


class SentinelGateProxy:
    """mitmproxy addon that scans all traffic through the DLP engine."""

    def __init__(self):
        self.scan_count = 0
        self.block_count = 0
        self.warn_count = 0
        self.allow_count = 0
        print(f"[SentinelGate Proxy] ✅ Initialized with {ENGINE_TYPE} engine")

    def _should_passthrough(self, host: str) -> bool:
        """Check if the request should bypass DLP scanning."""
        if not host:
            return True
        host_lower = host.lower()
        for domain in PASSTHROUGH_DOMAINS:
            if host_lower == domain or host_lower.endswith("." + domain):
                return True
        return False

    def _is_auth_flow(self, request: http.Request) -> bool:
        """Heuristic check for common authentication/login flows."""
        path_lower = request.path.lower()
        
        # Common authentication endpoints
        auth_keywords = [
            "/login", "/signin", "/sign-in", "/auth", "/oauth", 
            "/oauth2", "/sso", "/token", "/saml", "/register", "/signup", 
            "/sign-up", "/mfa", "/2fa", "/verify", "/session"
        ]
        
        for keyword in auth_keywords:
            if keyword in path_lower:
                return True
                
        # Heuristic for payload if it's small (e.g. < 1000 bytes) and looks like a login
        if request.content and len(request.content) < 1000:
            try:
                payload = request.content.decode("utf-8", errors="ignore").lower()
                if "grant_type=" in payload or "password=" in payload or "passwd=" in payload:
                    return True
            except Exception:
                pass
                
        return False

    def _get_content_type(self, headers) -> str:
        """Extract the base content type from headers."""
        ct = headers.get("content-type", "")
        return ct.split(";")[0].strip().lower()

    def _should_scan(self, flow: http.HTTPFlow) -> bool:
        """Determine if this request should be scanned."""
        request = flow.request

        # Skip if no body
        if not request.content or len(request.content) < MIN_SCAN_SIZE:
            return False

        # Skip passthrough domains
        if self._should_passthrough(request.host):
            return False

        # Heuristic check: skip login/auth flows
        if self._is_auth_flow(request):
            return False

        # Only scan certain content types
        content_type = self._get_content_type(request.headers)
        if content_type and not any(
            ct in content_type for ct in SCANNABLE_CONTENT_TYPES
        ):
            return False

        return True

    def _identify_source_app(self, flow: http.HTTPFlow) -> str:
        """Try to identify the source application from request headers."""
        ua = flow.request.headers.get("user-agent", "")
        ua_lower = ua.lower()

        if "chrome" in ua_lower and "edg" in ua_lower:
            return "Microsoft Edge"
        elif "chrome" in ua_lower:
            return "Google Chrome"
        elif "firefox" in ua_lower:
            return "Mozilla Firefox"
        elif "safari" in ua_lower:
            return "Safari"
        elif "electron" in ua_lower:
            return "Electron App"
        elif "whatsapp" in ua_lower:
            return "WhatsApp Desktop"
        elif "discord" in ua_lower:
            return "Discord"
        elif "slack" in ua_lower:
            return "Slack"
        elif "teams" in ua_lower:
            return "Microsoft Teams"
        elif "postman" in ua_lower:
            return "Postman"
        elif "curl" in ua_lower:
            return "cURL"
        elif "python" in ua_lower:
            return "Python (requests/urllib)"
        elif ua:
            # Return first part of user agent as app name
            return ua.split("/")[0][:30]
        else:
            return "Unknown App"

    def request(self, flow: http.HTTPFlow):
        """
        Called for every HTTP(S) request passing through the proxy.
        This is the main DLP interception point.
        """
        if not self._should_scan(flow):
            return

        # Decode the request body
        try:
            payload = flow.request.content.decode("utf-8", errors="replace")
        except Exception:
            return

        destination = flow.request.pretty_host
        source_app = self._identify_source_app(flow)
        self.scan_count += 1

        # ─── Run the DLP engine ───
        if dlp_engine:
            # Use the fast C++ engine
            scan_result, decision = dlp_engine.process_payload(payload, destination)
            action = decision.action
            reason = decision.reason
            triggered_rules = decision.triggered_rules
            detections = scan_result.detections
            highest_severity = scan_result.highest_severity
        else:
            # Fallback to Python engine
            scan_result = py_detection.scan(payload)
            decision = py_policy.evaluate(scan_result, destination)
            action = decision.action
            reason = decision.reason
            triggered_rules = decision.triggered_rules
            detections = scan_result.detections
            highest_severity = scan_result.highest_severity

        # ─── Context-Aware Heuristics ───
        # Allow pure email / password if it's NOT going to a chat app
        CHAT_DOMAINS = [
            "chatgpt.com", "openai.com", "anthropic.com", "claude.ai",
            "slack.com", "discord.com", "discordapp.com", "whatsapp.com",
            "whatsapp.net", "messenger.com", "web.telegram.org"
        ]
        
        def is_chat_app(dest: str) -> bool:
            dest_lower = dest.lower()
            return any(dest_lower == d or dest_lower.endswith("." + d) for d in CHAT_DOMAINS)

        if action in ("BLOCK", "WARN"):
            # Check what types of data were detected
            detected_types = set()
            for d in detections:
                if hasattr(d, 'data_type'):
                    detected_types.add(d.data_type)
                elif type(d) is dict and "data_type" in d:
                    detected_types.add(d["data_type"])
            
            # Rule 1: Ignore standalone emails entirely (too noisy, even for ChatGPT)
            if detected_types == {"Email Address"}:
                action = "ALLOW"
                reason = "Contextual Policy: Standalone email addresses are allowed."
            
            # Rule 2: Passwords are allowed ONLY if it's not a chat app
            # (e.g., logging into a random non-whitelisted site)
            elif "Password in Payload" in detected_types and not is_chat_app(destination):
                # Ensure there are no other high-severity items like API keys
                other_types = detected_types - {"Password in Payload", "Email Address"}
                if not other_types:
                    action = "ALLOW"
                    reason = "Contextual Policy: Allowed email/password to a non-chat website."
        try:
            sender_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"
        except Exception:
            sender_ip = "127.0.0.1"

        try:
            user_system_name = os.getlogin()
        except Exception:
            user_system_name = os.getenv("USERNAME", os.getenv("USER", "Unknown"))

        log_alert(
            sender_ip=sender_ip,
            user_system_name=user_system_name,
            source_app=source_app,
            destination=destination,
            action=action,
            highest_severity=highest_severity,
            detections=detections,
            payload=payload,
            triggered_rules=triggered_rules,
        )

        # ─── Act on the decision ───
        if action == "BLOCK":
            self.block_count += 1
            ctx.log.warn(
                f"[SentinelGate] ⛔ BLOCKED: {source_app} → {destination} "
                f"(severity: {highest_severity})"
            )

            # Build detection badges HTML
            det_badges = ""
            for d in detections:
                if dlp_engine:
                    det_badges += f'<span class="det-badge">{d.data_type} ({d.severity})</span>\n'
                else:
                    det_badges += f'<span class="det-badge">{d.data_type} ({d.severity})</span>\n'

            # Return a block page for browser requests, or 403 for API calls
            accept = flow.request.headers.get("accept", "")
            if "text/html" in accept:
                block_html = BLOCK_PAGE_HTML.format(
                    destination=destination,
                    source_app=source_app,
                    reason=reason,
                    detection_badges=det_badges,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
                flow.response = http.Response.make(
                    403,
                    block_html.encode("utf-8"),
                    {"Content-Type": "text/html; charset=utf-8"},
                )
            else:
                block_json = json.dumps({
                    "blocked_by": "SentinelGate DLP",
                    "action": "BLOCK",
                    "reason": reason,
                    "destination": destination,
                    "triggered_rules": triggered_rules,
                    "detections": [
                        {"type": d.data_type, "severity": d.severity}
                        for d in detections
                    ],
                })
                flow.response = http.Response.make(
                    403,
                    block_json.encode("utf-8"),
                    {"Content-Type": "application/json"},
                )

        elif action == "WARN":
            self.warn_count += 1
            ctx.log.warn(
                f"[SentinelGate] ⚠️ WARN: {source_app} → {destination} "
                f"(severity: {highest_severity})"
            )
            # Add a warning header but allow the request
            flow.request.headers["X-SentinelGate-Warning"] = (
                f"Sensitive data detected: {highest_severity}"
            )

        else:
            self.allow_count += 1

    def error(self, flow: http.HTTPFlow):
        """
        Called when a flow error occurs. This happens when apps with 
        Certificate Pinning (like WhatsApp Desktop) reject our proxy certificate 
        and drop the connection before sending data.
        """
        if not flow.error:
            return

        msg = str(flow.error.msg).lower()
        # Certificate pinning usually results in a TLS handshake failure or remote disconnect
        if "certificate" in msg or "tls" in msg or "handshake" in msg or "reset by peer" in msg or "closed before full" in msg:
            destination = flow.request.pretty_host if flow.request else "unknown"
            
            # Skip noise or passthrough domains
            if getattr(self, "_should_passthrough", lambda h: False)(destination):
                return
                
            source_app = self._identify_source_app(flow) if flow.request else "Unknown App"
            
            # If the app didn't send a User-Agent because it rejected the handshake, 
            # we can guess the app based on the destination SNI
            dest_lower = destination.lower()
            if source_app == "Unknown App":
                if "whatsapp" in dest_lower:
                    source_app = "WhatsApp Desktop (Pinned)"
                elif "chatgpt" in dest_lower or "openai" in dest_lower:
                    source_app = "ChatGPT Desktop (Pinned)"
                elif "discord" in dest_lower:
                    source_app = "Discord Desktop (Pinned)"
                elif "slack" in dest_lower:
                    source_app = "Slack Desktop (Pinned)"
                else:
                    source_app = f"Pinned App ({destination})"
                    
            # Prevent logging the same host a thousand times a second
            if not hasattr(self, "_recent_errors"):
                self._recent_errors = {}
                
            now = datetime.now()
            last_logged = self._recent_errors.get(destination)
            if last_logged and (now - last_logged).total_seconds() < 60:
                return # Only log once per minute per host
                
            self._recent_errors[destination] = now
            
            try:
                sender_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"
            except Exception:
                sender_ip = "127.0.0.1"

            try:
                user_system_name = os.getlogin()
            except Exception:
                user_system_name = os.getenv("USERNAME", os.getenv("USER", "Unknown"))

            # Create a mock detection object since we don't have python detection classes here
            class MockDetection:
                def __init__(self, data_type, redacted_value, severity, description):
                    self.data_type = data_type
                    self.redacted_value = redacted_value
                    self.severity = severity
                    self.description = description

            log_alert(
                sender_ip=sender_ip,
                user_system_name=user_system_name,
                source_app=source_app,
                destination=destination,
                action="WARN",
                highest_severity="LOW",
                detections=[
                    MockDetection(
                        data_type="Unscannable App",
                        redacted_value="[Encrypted Connection]",
                        severity="LOW",
                        description="App uses Certificate Pinning. Traffic cannot be inspected."
                    )
                ],
                payload=f"<Encrypted Traffic Dropped by App: {flow.error.msg}>",
                triggered_rules=["Certificate Pinning Detected"],
            )

# Register the addon with mitmproxy
addons = [SentinelGateProxy()]
