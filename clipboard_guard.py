"""
SentinelGate - Clipboard Guard
Monitors the Windows clipboard in real-time. Blocks pasting of sensitive data
into ALL applications EXCEPT whitelisted developer tools (text editors, VS Code,
terminals, IDEs). System-wide protection by default.

Runs as a background thread integrated into the SentinelGate service.
"""

import threading
import time
import ctypes
import ctypes.wintypes
import os
import sys
import json
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# ─── Import the C++ DLP engine ───────────────────────────────────────────────
try:
    import sentinel_engine_cpp
    _engine = sentinel_engine_cpp.SentinelEngine()
    print("[ClipboardGuard] C++ DLP engine loaded")
except ImportError:
    _engine = None
    print("[ClipboardGuard] C++ engine not available, using Python fallback")

if _engine is None:
    try:
        from detection_engine import DetectionEngine
        from policy_engine import PolicyEngine
        _py_detection = DetectionEngine()
        _py_policy = PolicyEngine()
    except ImportError:
        _py_detection = None
        _py_policy = None


# ─── Import alert logger ─────────────────────────────────────────────────────
try:
    from alert_logger import log_alert
except ImportError:
    def log_alert(**kwargs):
        pass


# ─── Win32 API constants ─────────────────────────────────────────────────────
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


# ─── WHITELISTED apps where sensitive paste IS allowed ────────────────────────
# Everything NOT in this list will have sensitive pastes BLOCKED.
PASTE_ALLOWED_APPS = {
    # Text Editors & IDEs (you need to paste secrets in code/configs)
    "code.exe",                 # VS Code
    "code - insiders.exe",      # VS Code Insiders
    "devenv.exe",               # Visual Studio
    "rider64.exe",              # JetBrains Rider
    "idea64.exe",               # IntelliJ IDEA
    "pycharm64.exe",            # PyCharm
    "webstorm64.exe",           # WebStorm
    "goland64.exe",             # GoLand
    "clion64.exe",              # CLion
    "phpstorm64.exe",           # PhpStorm
    "rubymine64.exe",           # RubyMine
    "datagrip64.exe",           # DataGrip
    "sublime_text.exe",         # Sublime Text
    "notepad++.exe",            # Notepad++
    "notepad.exe",              # Windows Notepad
    "atom.exe",                 # Atom
    "cursor.exe",               # Cursor IDE
    "windsurf.exe",             # Windsurf IDE
    "zed.exe",                  # Zed editor

    # Terminals & Shells
    "windowsterminal.exe",      # Windows Terminal
    "cmd.exe",                  # Command Prompt
    "powershell.exe",           # PowerShell
    "pwsh.exe",                 # PowerShell Core
    "conhost.exe",              # Console Host
    "wt.exe",                   # Windows Terminal (alt)
    "mintty.exe",               # Git Bash / MinTTY
    "alacritty.exe",            # Alacritty
    "wezterm-gui.exe",          # WezTerm
    "hyper.exe",                # Hyper terminal

    # Antigravity / AI Coding Assistants (this tool)
    "antigravity.exe",
    "electron.exe",             # Electron-based IDEs

    # Database & API Tools (devs paste connection strings here)
    "postman.exe",              # Postman
    "insomnia.exe",             # Insomnia
    "dbeaver.exe",              # DBeaver
    "pgadmin4.exe",             # pgAdmin
    "ssms.exe",                 # SQL Server Management Studio
    "mysql.exe",                # MySQL CLI
    "psql.exe",                 # PostgreSQL CLI
    "mongosh.exe",              # MongoDB Shell

    # SentinelGate itself
    "sentinelgate.exe",
    "python.exe",               # Python (running SentinelGate)
    "pythonw.exe",

    # File managers & system tools (pasting file paths etc.)
    "explorer.exe",             # Windows Explorer
    "totalcmd.exe",             # Total Commander

    # Password Managers (MUST allow paste for copying passwords)
    "bitwarden.exe",
    "1password.exe",
    "keepass.exe",
    "keepassxc.exe",
    "lastpass.exe",
}

# Browser title keywords that indicate whitelisted pages (dev tools in browser)
BROWSER_ALLOWED_TITLES = [
    "localhost",
    "127.0.0.1",
    "devtools",
    "developer tools",
    "sentinelgate",
    "github.com",           # Allow pasting in code repos
    "gitlab.com",
    "bitbucket.org",
    "codepen",
    "codesandbox",
    "stackblitz",
    "replit",
    "jsfiddle",
    "vscode.dev",
    "github.dev",
]


# ─── Win32 Clipboard Functions ───────────────────────────────────────────────
def get_clipboard_text():
    """Read the current clipboard text content."""
    try:
        if not user32.OpenClipboard(0):
            return None
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                text = ctypes.wstring_at(ptr)
                return text
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    except Exception:
        return None


def set_clipboard_text(text):
    """Replace clipboard content with the given text."""
    try:
        if not user32.OpenClipboard(0):
            return False
        try:
            user32.EmptyClipboard()
            if text:
                encoded = text.encode("utf-16-le") + b"\x00\x00"
                h = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
                ptr = kernel32.GlobalLock(h)
                ctypes.memmove(ptr, encoded, len(encoded))
                kernel32.GlobalUnlock(h)
                user32.SetClipboardData(CF_UNICODETEXT, h)
            return True
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


def get_foreground_app():
    """Get the process name and window title of the currently focused window."""
    try:
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None, None

        # Get window title
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value

        # Get process ID
        pid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

        # Get process name from PID
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        h_process = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid.value
        )
        if not h_process:
            return None, title

        try:
            psapi = ctypes.windll.psapi
            module_name = ctypes.create_unicode_buffer(260)
            psapi.GetModuleBaseNameW(h_process, None, module_name, 260)
            return module_name.value.lower(), title
        finally:
            kernel32.CloseHandle(h_process)

    except Exception:
        return None, None


def is_paste_allowed_app(process_name, window_title):
    """
    Check if the foreground app is WHITELISTED (paste allowed).
    Returns (is_allowed, app_display_name).
    
    Logic: BLOCK everywhere EXCEPT whitelisted dev tools.
    """
    if not process_name and not window_title:
        return False, window_title or "Unknown App"

    # Check if process is in the whitelist
    if process_name and process_name in PASTE_ALLOWED_APPS:
        return True, process_name

    # Check browser windows — allow if on a whitelisted dev page
    if window_title:
        title_lower = window_title.lower()
        browser_processes = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe"]
        is_browser = process_name in browser_processes if process_name else False

        if is_browser:
            # Check if the browser tab is on a whitelisted page
            for keyword in BROWSER_ALLOWED_TITLES:
                if keyword in title_lower:
                    return True, f"{keyword} (Browser)"

    # Not in whitelist → paste is BLOCKED
    # Build a nice display name
    display_name = window_title or process_name or "Unknown App"
    if len(display_name) > 40:
        display_name = display_name[:37] + "..."
    return False, display_name


# ─── DLP Scanning ─────────────────────────────────────────────────────────────
def scan_text(text):
    """Scan text through the DLP engine. Returns (is_sensitive, action, detections, severity)."""
    if not text or len(text.strip()) < 4:
        return False, "ALLOW", [], None

    try:
        if _engine:
            # Use the C++ engine
            result = _engine.process_payload(text, "clipboard")
            scan_result, policy_result = result

            detections = []
            for d in scan_result.detections:
                detections.append({
                    "data_type": d.data_type,
                    "redacted_value": d.redacted_value,
                    "severity": d.severity,
                    "description": d.description,
                })

            return (
                scan_result.is_sensitive,
                policy_result.action,
                detections,
                scan_result.highest_severity,
            )
        elif _py_detection and _py_policy:
            # Python fallback
            scan_result = _py_detection.scan(text)
            decision = _py_policy.evaluate(scan_result, "clipboard")

            detections = []
            for d in scan_result.detections:
                detections.append({
                    "data_type": d.data_type,
                    "redacted_value": d.redacted_value,
                    "severity": d.severity,
                    "description": d.description,
                })

            return (
                scan_result.is_sensitive,
                decision.action,
                detections,
                scan_result.highest_severity,
            )
    except Exception as e:
        print(f"[ClipboardGuard] Scan error: {e}")

    return False, "ALLOW", [], None


# ─── Redact clipboard content ────────────────────────────────────────────────
def redact_clipboard(text, detections):
    """Replace sensitive portions in clipboard text with [REDACTED] markers."""
    redacted = text
    for det in detections:
        # The redacted_value has format: abc***xyz
        # We need to find the original value — for now, replace known patterns
        pass
    # Simpler approach: just clear the clipboard entirely with a warning message
    return "[SentinelGate BLOCKED] Sensitive data removed from clipboard. Detected: " + \
           ", ".join(d["data_type"] for d in detections)


# ─── Windows Toast Notification ──────────────────────────────────────────────
def show_notification(title, message, severity="BLOCK"):
    """Show a Windows balloon notification via PowerShell."""
    try:
        # Use PowerShell to show a balloon tip notification
        icon = "Error" if severity == "BLOCK" else "Warning"
        ps_script = f'''
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        $notify = New-Object System.Windows.Forms.NotifyIcon
        $notify.Icon = [System.Drawing.SystemIcons]::Shield
        $notify.Visible = $true
        $notify.BalloonTipTitle = '{title.replace("'", "")}'
        $notify.BalloonTipText = '{message.replace("'", "")}'
        $notify.BalloonTipIcon = '{icon}'
        $notify.ShowBalloonTip(5000)
        Start-Sleep -Seconds 6
        $notify.Dispose()
        '''
        import subprocess
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
    except Exception as e:
        print(f"[ClipboardGuard] Notification error: {e}")


# ─── Clipboard Guard Thread ──────────────────────────────────────────────────
class ClipboardGuard:
    """
    System-wide clipboard DLP guard with two-phase protection:
    
    Phase 1 (on copy): When clipboard content changes, scan it through DLP
             and cache the result.
    Phase 2 (continuous): Every poll cycle, if clipboard is flagged sensitive,
             check the foreground app. If it's NOT whitelisted, immediately
             sanitize the clipboard BEFORE the user can paste.
    
    Also uses a low-level keyboard hook to catch Ctrl+V as a secondary trap.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self._hook_thread = None
        self._block_count = 0
        self._scan_count = 0
        self._enabled = True

        # Track clipboard state
        self._get_seq = user32.GetClipboardSequenceNumber
        self._clipboard_is_sensitive = False
        self._cached_detections = []
        self._cached_severity = None
        self._cached_action = None
        self._cached_clip_text = ""
        self._last_seq = 0
        self._already_blocked_seq = 0  # Prevent re-blocking our own replacement

    def start(self):
        """Start the clipboard guard in background threads."""
        if self._running:
            return
        self._running = True
        self._last_seq = self._get_seq()

        # Main polling thread
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ClipboardGuard")
        self._thread.start()

        # Keyboard hook thread (Ctrl+V interceptor)
        self._hook_thread = threading.Thread(target=self._keyboard_hook_loop, daemon=True, name="ClipboardHook")
        self._hook_thread.start()

        print("[ClipboardGuard] Clipboard Guard ACTIVE - system-wide paste protection")

    def stop(self):
        """Stop the clipboard guard."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        print("[ClipboardGuard] Clipboard Guard stopped")

    def _scan_clipboard(self):
        """Scan current clipboard content and cache the result."""
        clip_text = get_clipboard_text()
        if not clip_text or len(clip_text.strip()) < 4:
            self._clipboard_is_sensitive = False
            self._cached_detections = []
            self._cached_clip_text = ""
            return

        self._cached_clip_text = clip_text
        is_sensitive, action, detections, severity = scan_text(clip_text)
        self._scan_count += 1

        self._clipboard_is_sensitive = is_sensitive and action in ("BLOCK", "WARN")
        self._cached_detections = detections
        self._cached_severity = severity
        self._cached_action = action

        if self._clipboard_is_sensitive:
            det_names = ", ".join(d["data_type"] for d in detections[:3])
            print(f"[ClipboardGuard] Sensitive data DETECTED in clipboard: {det_names}")

    def _block_paste(self, app_name):
        """Sanitize clipboard and notify user."""
        if not self._cached_clip_text or not self._cached_detections:
            return

        detection_names = ", ".join(d["data_type"] for d in self._cached_detections[:3])
        redacted_msg = redact_clipboard(self._cached_clip_text, self._cached_detections)
        set_clipboard_text(redacted_msg)

        # Mark this sequence as our own replacement (don't re-scan it)
        self._already_blocked_seq = self._get_seq()

        self._clipboard_is_sensitive = False
        self._block_count += 1

        # Show notification
        show_notification(
            "SentinelGate - Paste Blocked",
            f"Sensitive data ({detection_names}) blocked from {app_name}.",
            severity="BLOCK",
        )

        # Log to database
        try:
            import socket
            sender_ip = socket.gethostbyname(socket.gethostname())
            user_system_name = os.environ.get("USERNAME", os.environ.get("USER", "Unknown"))
            log_alert(
                sender_ip=sender_ip,
                user_system_name=user_system_name,
                source_app=f"Clipboard -> {app_name}",
                destination=app_name,
                action="BLOCK",
                highest_severity=self._cached_severity or "HIGH",
                detections=self._cached_detections,
                payload=f"[CLIPBOARD PASTE BLOCKED] {self._cached_clip_text[:100]}...",
                triggered_rules=[f"Clipboard paste to {app_name}"],
            )
        except Exception as e:
            print(f"[ClipboardGuard] Log error: {e}")

        print(f"[ClipboardGuard] BLOCKED paste to {app_name}: {detection_names}")

    def _monitor_loop(self):
        """
        Main polling loop - two-phase monitoring:
        1. On clipboard change → scan and cache result
        2. Every cycle → if sensitive, check foreground app and block if needed
        """
        while self._running:
            try:
                if not self._enabled:
                    time.sleep(1)
                    continue

                # ── Phase 1: Check for clipboard changes ──
                current_seq = self._get_seq()
                if current_seq != self._last_seq:
                    self._last_seq = current_seq

                    # Skip if this is our own sanitization write
                    if current_seq == self._already_blocked_seq:
                        time.sleep(0.3)
                        continue

                    # New clipboard content — scan it
                    self._scan_clipboard()

                # ── Phase 2: Continuous foreground app monitoring ──
                # If clipboard has sensitive data, check where the user is RIGHT NOW
                if self._clipboard_is_sensitive:
                    process_name, window_title = get_foreground_app()
                    is_allowed, app_name = is_paste_allowed_app(process_name, window_title)

                    if not is_allowed:
                        # User is in a non-whitelisted app with sensitive clipboard!
                        # Sanitize clipboard IMMEDIATELY before they can paste
                        self._block_paste(app_name)

                time.sleep(0.3)  # Poll every 300ms for responsiveness

            except Exception as e:
                print(f"[ClipboardGuard] Error: {e}")
                time.sleep(2)

    def _keyboard_hook_loop(self):
        """
        Low-level keyboard hook to catch Ctrl+V as a secondary safety net.
        This runs in its own thread with a Windows message loop.
        """
        try:
            import ctypes
            from ctypes import wintypes

            # Callback type for low-level keyboard hook
            HOOKPROC = ctypes.CFUNCTYPE(
                ctypes.c_long,        # return LRESULT
                ctypes.c_int,         # nCode
                wintypes.WPARAM,      # wParam
                wintypes.LPARAM,      # lParam
            )

            WH_KEYBOARD_LL = 13
            WM_KEYDOWN = 0x0100
            VK_V = 0x56
            VK_CONTROL = 0x11

            def hook_callback(nCode, wParam, lParam):
                """Called on every keypress system-wide."""
                try:
                    if nCode >= 0 and wParam == WM_KEYDOWN:
                        # lParam is pointer to KBDLLHOOKSTRUCT
                        vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong))[0]

                        # Check if Ctrl is held + V is pressed
                        ctrl_pressed = user32.GetAsyncKeyState(VK_CONTROL) & 0x8000
                        if vk_code == VK_V and ctrl_pressed:
                            # Ctrl+V detected! Check if we need to block
                            if self._enabled and self._clipboard_is_sensitive:
                                process_name, window_title = get_foreground_app()
                                is_allowed, app_name = is_paste_allowed_app(process_name, window_title)
                                if not is_allowed:
                                    self._block_paste(app_name)
                except Exception:
                    pass

                return user32.CallNextHookEx(None, nCode, wParam, lParam)

            # Keep a reference to prevent garbage collection
            self._hook_proc = HOOKPROC(hook_callback)

            # Install the hook
            hook = user32.SetWindowsHookExW(
                WH_KEYBOARD_LL,
                self._hook_proc,
                None,  # hMod (None = current thread)
                0,     # dwThreadId (0 = all threads)
            )

            if not hook:
                print("[ClipboardGuard] Keyboard hook failed, relying on polling only")
                return

            print("[ClipboardGuard] Keyboard hook installed (Ctrl+V interceptor)")

            # Run Windows message loop (required for hooks to work)
            msg = wintypes.MSG()
            while self._running:
                result = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if result <= 0:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            # Unhook when stopping
            user32.UnhookWindowsHookEx(hook)

        except Exception as e:
            print(f"[ClipboardGuard] Hook thread error: {e}, relying on polling")

    @property
    def stats(self):
        """Get clipboard guard statistics."""
        return {
            "enabled": self._enabled,
            "scans": self._scan_count,
            "blocks": self._block_count,
            "running": self._running,
        }

    def enable(self):
        self._enabled = True
        print("[ClipboardGuard] ▶ Clipboard Guard enabled")

    def disable(self):
        self._enabled = False
        print("[ClipboardGuard] ⏸ Clipboard Guard paused")


# ─── Global instance ─────────────────────────────────────────────────────────
_guard_instance = None


def get_clipboard_guard():
    """Get or create the global ClipboardGuard instance."""
    global _guard_instance
    if _guard_instance is None:
        _guard_instance = ClipboardGuard()
    return _guard_instance


def start_clipboard_guard():
    """Start the global clipboard guard."""
    guard = get_clipboard_guard()
    guard.start()
    return guard


if __name__ == "__main__":
    print("═" * 60)
    print("  🛡️  SentinelGate Clipboard Guard — Standalone Mode")
    print("═" * 60)
    print()
    print("  Monitoring clipboard for sensitive data...")
    print("  Paste will be blocked in: WhatsApp, ChatGPT, Slack, etc.")
    print("  Press Ctrl+C to stop.")
    print()

    guard = start_clipboard_guard()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        guard.stop()
        print("\n[ClipboardGuard] Stopped.")
