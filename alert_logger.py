"""
SentinelGate - Alert Logger
Persists alerts to SQLite and exposes an API for the dashboard.
"""

import sqlite3
import json
import os
import subprocess
import threading
from datetime import datetime
from typing import List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelgate.db")


# ─── Known Apps to Monitor ───────────────────────────────────────────────────
MONITORED_APPS = {
    # Process name (lowercase) → Display name, Category, Scannable by proxy?
    "whatsapp.exe":       ("WhatsApp Desktop",   "Messaging",    False),
    "telegram.exe":       ("Telegram Desktop",   "Messaging",    False),
    "discord.exe":        ("Discord",            "Messaging",    True),
    "slack.exe":          ("Slack",              "Messaging",    True),
    "teams.exe":          ("Microsoft Teams",    "Messaging",    True),
    "ms-teams.exe":       ("Microsoft Teams",    "Messaging",    True),
    "signal.exe":         ("Signal",             "Messaging",    False),
    "chatgpt.exe":        ("ChatGPT Desktop",    "AI Assistant", False),
    "claude.exe":         ("Claude Desktop",     "AI Assistant", False),
    "copilot.exe":        ("Microsoft Copilot",  "AI Assistant", False),
    "chrome.exe":         ("Google Chrome",      "Browser",      True),
    "msedge.exe":         ("Microsoft Edge",     "Browser",      True),
    "firefox.exe":        ("Mozilla Firefox",    "Browser",      True),
    "brave.exe":          ("Brave Browser",      "Browser",      True),
    "opera.exe":          ("Opera Browser",      "Browser",      True),
    "code.exe":           ("VS Code",            "Development",  True),
    "postman.exe":        ("Postman",            "Development",  True),
    "insomnia.exe":       ("Insomnia",           "Development",  True),
    "outlook.exe":        ("Microsoft Outlook",  "Email",        True),
    "thunderbird.exe":    ("Thunderbird",        "Email",        True),
    "filezilla.exe":      ("FileZilla",          "File Transfer",True),
    "winscp.exe":         ("WinSCP",             "File Transfer",True),
    "notion.exe":         ("Notion",             "Productivity", True),
    "obsidian.exe":       ("Obsidian",           "Productivity", True),
}


class DBManager:
    """Singleton Database Connection Manager for thread-safe SQLite access."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DBManager, cls).__new__(cls)
                cls._instance._init_connection()
            return cls._instance

    def _init_connection(self):
        # check_same_thread=False allows multiple threads (like Flask) to share the connection
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._db_lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._db_lock:
            with self.conn:
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        sender_ip TEXT,
                        user_system_name TEXT,
                        source_app TEXT,
                        destination TEXT,
                        action TEXT NOT NULL,
                        highest_severity TEXT,
                        detections_json TEXT NOT NULL,
                        payload_preview TEXT,
                        triggered_rules TEXT
                    )
                """)
                self.conn.execute("""
                    CREATE TABLE IF NOT EXISTS app_monitor (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        process_name TEXT NOT NULL,
                        app_name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        scannable INTEGER NOT NULL DEFAULT 0,
                        status TEXT NOT NULL DEFAULT 'running'
                    )
                """)

    def execute(self, query: str, params: tuple = ()):
        with self._db_lock:
            with self.conn:
                return self.conn.execute(query, params)

    def fetchall(self, query: str, params: tuple = ()):
        with self._db_lock:
            return self.conn.execute(query, params).fetchall()

    def fetchone(self, query: str, params: tuple = ()):
        with self._db_lock:
            return self.conn.execute(query, params).fetchone()


# Initialize the global DB manager once
db = DBManager()


def log_alert(
    sender_ip: str,
    user_system_name: str,
    source_app: str,
    destination: str,
    action: str,
    highest_severity: str,
    detections: list,
    payload: str,
    triggered_rules: list,
):
    preview = payload
    if len(payload) > 8:
        visible_front = min(6, len(payload) // 3)
        visible_back = min(4, len(payload) // 4)
        masked_core = "*" * (len(payload) - visible_front - visible_back)
        preview = payload[:visible_front] + masked_core + payload[-visible_back:]
        
    if len(preview) > 120:
        preview = preview[:117] + "..."
    detections_data = [
        {
            "data_type": d.data_type,
            "redacted_value": d.redacted_value,
            "severity": d.severity,
            "description": d.description,
        }
        for d in detections
    ]
    
    query = """
        INSERT INTO alerts
            (timestamp, sender_ip, user_system_name, source_app, destination, action, highest_severity,
             detections_json, payload_preview, triggered_rules)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        datetime.utcnow().isoformat(),
        sender_ip or "Unknown",
        user_system_name or "Unknown",
        source_app or "Unknown",
        destination or "Unknown",
        action,
        highest_severity or "NONE",
        json.dumps(detections_data),
        preview,
        json.dumps(triggered_rules),
    )
    db.execute(query, params)


def get_recent_alerts(limit: int = 100) -> List[Dict[str, Any]]:
    rows = db.fetchall(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    result = []
    for row in rows:
        d = dict(row)
        d["detections"] = json.loads(d["detections_json"])
        d["triggered_rules"] = json.loads(d["triggered_rules"])
        del d["detections_json"]
        result.append(d)
    return result


def get_stats() -> Dict[str, Any]:
    total = db.fetchone("SELECT COUNT(*) as total FROM alerts")["total"]
    blocked = db.fetchone("SELECT COUNT(*) as blocked FROM alerts WHERE action='BLOCK'")["blocked"]
    warned = db.fetchone("SELECT COUNT(*) as warned FROM alerts WHERE action='WARN'")["warned"]
    allowed = db.fetchone("SELECT COUNT(*) as allowed FROM alerts WHERE action='ALLOW'")["allowed"]
    
    severity_rows = db.fetchall("SELECT highest_severity, COUNT(*) as cnt FROM alerts GROUP BY highest_severity")
    by_severity = {row["highest_severity"]: row["cnt"] for row in severity_rows}
    
    return {
        "total": total,
        "blocked": blocked,
        "warned": warned,
        "allowed": allowed,
        "by_severity": by_severity,
    }


def clear_alerts():
    db.execute("DELETE FROM alerts")
    db.execute("DELETE FROM app_monitor")


# ─── App Monitor Functions ───────────────────────────────────────────────────

def scan_running_apps() -> List[Dict[str, Any]]:
    """Scan currently running processes and return detected monitored apps."""
    detected = []
    try:
        output = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        
        running_processes = set()
        for line in output.strip().split("\n"):
            parts = line.strip().strip('"').split('","')
            if parts:
                proc_name = parts[0].lower().strip('"')
                running_processes.add(proc_name)
        
        now = datetime.utcnow().isoformat()
        
        for proc_name, (app_name, category, scannable) in MONITORED_APPS.items():
            if proc_name in running_processes:
                detected.append({
                    "process_name": proc_name,
                    "app_name": app_name,
                    "category": category,
                    "scannable": scannable,
                    "status": "running",
                    "timestamp": now,
                })
    except Exception as e:
        print(f"[AppMonitor] Error scanning processes: {e}")
    
    return detected


def log_running_apps():
    """Scan running apps and log them to the database."""
    apps = scan_running_apps()
    now = datetime.utcnow().isoformat()
    
    for app in apps:
        db.execute(
            """INSERT INTO app_monitor 
               (timestamp, process_name, app_name, category, scannable, status) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now, app["process_name"], app["app_name"], app["category"],
             1 if app["scannable"] else 0, app["status"])
        )
    return apps


def get_running_apps() -> List[Dict[str, Any]]:
    """Get currently running monitored apps (live scan)."""
    return scan_running_apps()


def get_app_history(limit: int = 200) -> List[Dict[str, Any]]:
    """Get recent app monitoring history from the database."""
    rows = db.fetchall(
        "SELECT * FROM app_monitor ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    return [dict(row) for row in rows]
