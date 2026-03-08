"""
SentinelGate - Unified Service Launcher
Starts both the MITM proxy and the Dashboard in a single process.
Handles graceful shutdown: disables system proxy on exit to avoid
leaving the system in a broken state.

Usage:
    python sentinelgate_service.py          # Start everything
    python sentinelgate_service.py --no-proxy  # Dashboard only (no proxy, for dev)
"""

import sys
import os
import signal
import time
import subprocess
import threading
import argparse
import atexit

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from proxy_manager import (
    enable_system_proxy,
    disable_system_proxy,
    is_proxy_active,
    is_ca_installed,
    install_mitmproxy_ca,
    get_current_proxy_settings,
    PROXY_HOST,
    PROXY_PORT,
)

# ─── Configuration ─────────────────────────────────────────────────────────
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000
MITM_PORT = PROXY_PORT  # 8081
ADDON_SCRIPT = os.path.join(SCRIPT_DIR, "proxy_addon.py")

# Store the original proxy settings to restore on exit
_original_proxy_settings = None
_proxy_process = None
_shutdown_initiated = False


def _graceful_shutdown(signum=None, frame=None):
    """Ensure system proxy is disabled on exit."""
    global _shutdown_initiated, _proxy_process
    if _shutdown_initiated:
        return
    _shutdown_initiated = True

    print("\n[SentinelGate] 🔻 Shutting down gracefully...")

    # Disable system proxy first
    try:
        disable_system_proxy()
    except Exception as e:
        print(f"[SentinelGate] ⚠️ Error disabling proxy: {e}")

    # Kill the mitmproxy process
    if _proxy_process and _proxy_process.poll() is None:
        print("[SentinelGate] Stopping proxy process...")
        _proxy_process.terminate()
        try:
            _proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _proxy_process.kill()

    print("[SentinelGate] ✅ Shutdown complete. Normal connectivity restored.")
    os._exit(0)


def start_mitm_proxy():
    """
    Start the mitmproxy process with our DLP addon.
    Runs as a subprocess so we can manage its lifecycle.
    """
    global _proxy_process

    cmd = [
        sys.executable, "-m", "mitmproxy.tools.main",
        "mitmdump",
        "--listen-host", PROXY_HOST,
        "--listen-port", str(MITM_PORT),
        "--set", f"confdir={os.path.expanduser('~/.mitmproxy')}",
        "--scripts", ADDON_SCRIPT,
        "--set", "stream_large_bodies=1m",     # Stream large bodies instead of buffering
        "--set", "connection_strategy=lazy",    # Only connect when needed
        "--quiet",                              # Reduce log noise
    ]

    # Use mitmdump directly if available
    mitmdump_cmd = [
        "mitmdump",
        "--listen-host", PROXY_HOST,
        "--listen-port", str(MITM_PORT),
        "--scripts", ADDON_SCRIPT,
        "--set", "stream_large_bodies=1m",
        "--set", "connection_strategy=lazy",
        "--quiet",
    ]

    print(f"[SentinelGate] Starting MITM proxy on {PROXY_HOST}:{MITM_PORT}...")

    try:
        _proxy_process = subprocess.Popen(
            mitmdump_cmd,
            cwd=SCRIPT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # Stream proxy output in background
        def _stream_output():
            for line in iter(_proxy_process.stdout.readline, b""):
                decoded = line.decode("utf-8", errors="replace").strip()
                if decoded:
                    print(f"  [Proxy] {decoded}")

        output_thread = threading.Thread(target=_stream_output, daemon=True)
        output_thread.start()

        # Wait a moment to check if it started successfully
        time.sleep(2)
        if _proxy_process.poll() is not None:
            print("[SentinelGate] ❌ Proxy process exited early! Check mitmproxy installation.")
            return False

        print(f"[SentinelGate] ✅ MITM Proxy running (PID: {_proxy_process.pid})")
        return True

    except FileNotFoundError:
        print("[SentinelGate] ❌ mitmdump not found! Install it with: pip install mitmproxy")
        return False
    except Exception as e:
        print(f"[SentinelGate] ❌ Failed to start proxy: {e}")
        return False


def start_dashboard():
    """Start the Flask dashboard server."""
    # Import and run the Flask app
    from dashboard import app, HOST, PORT

    print(f"[SentinelGate] Starting Dashboard on http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


def print_banner():
    """Print the SentinelGate startup banner."""
    banner = r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🛡️  S E N T I N E L G A T E                                ║
    ║   ─────────────────────────────                               ║
    ║   Pre-Network Data Leak Protection System                     ║
    ║                                                               ║
    ║   Mode:  System-Wide Proxy (ALL traffic)                      ║
    ║   Engine: C++ Native DLP + Shannon Entropy                    ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    global _original_proxy_settings

    parser = argparse.ArgumentParser(description="SentinelGate Service Launcher")
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Start dashboard only without the system-wide proxy",
    )
    parser.add_argument(
        "--install-ca",
        action="store_true",
        help="Install the mitmproxy CA certificate and exit",
    )
    args = parser.parse_args()

    print_banner()

    # ─── CA Certificate Installation ───
    if args.install_ca:
        install_mitmproxy_ca()
        return

    # ─── Register shutdown handlers ───
    signal.signal(signal.SIGINT, _graceful_shutdown)
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    atexit.register(disable_system_proxy)

    if not args.no_proxy:
        # ─── Check for mitmproxy CA ───
        if not is_ca_installed():
            print("[SentinelGate] ⚠️  mitmproxy CA certificate not found.")
            print("[SentinelGate]    The proxy will generate it on first run.")
            print("[SentinelGate]    After first run, install it with:")
            print(f"[SentinelGate]    python {os.path.basename(__file__)} --install-ca")
            print()

        # ─── Save original proxy settings ───
        _original_proxy_settings = get_current_proxy_settings()
        print(f"[SentinelGate] 📋 Backed up original proxy settings")

        # ─── Start the MITM Proxy ───
        proxy_ok = start_mitm_proxy()
        if not proxy_ok:
            print("[SentinelGate] ❌ Cannot start without proxy. Exiting.")
            print("[SentinelGate] 💡 Install mitmproxy: pip install mitmproxy")
            sys.exit(1)

        # ─── Enable the system-wide proxy ───
        if not enable_system_proxy():
            print("[SentinelGate] ⚠️ Could not set system proxy. Traffic may not be intercepted.")

        print()

    if not args.no_proxy:
        print("  ┌─────────────────────────────────────────────────────────┐")
        print(f"  │  🌐 Dashboard:   http://{DASHBOARD_HOST}:{DASHBOARD_PORT}           │")
        print(f"  │  🔒 Proxy:       {PROXY_HOST}:{MITM_PORT} (system-wide)         │")
        print("  │  📊 Status:      ALL traffic is being scanned          │")
        print("  │                                                         │")
        print("  │  Press Ctrl+C to stop and restore network settings      │")
        print("  └─────────────────────────────────────────────────────────┘")
        print()
    else:
        print("  ┌─────────────────────────────────────────────────────────┐")
        print(f"  │  🌐 Dashboard:   http://{DASHBOARD_HOST}:{DASHBOARD_PORT}           │")
        print("  │  🔒 Proxy:       DISABLED (--no-proxy mode)            │")
        print("  │                                                         │")
        print("  │  Press Ctrl+C to stop                                   │")
        print("  └─────────────────────────────────────────────────────────┘")
        print()

    # ─── Start the Dashboard (in background thread) ───
    dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
    dashboard_thread.start()

    # ─── Keep the main thread alive ───
    try:
        while True:
            # Check if the proxy is still running
            if not args.no_proxy and _proxy_process and _proxy_process.poll() is not None:
                print("[SentinelGate] ⚠️ Proxy process exited unexpectedly!")
                print("[SentinelGate] Attempting to restart...")
                proxy_ok = start_mitm_proxy()
                if not proxy_ok:
                    print("[SentinelGate] ❌ Could not restart proxy.")
                    _graceful_shutdown()
            time.sleep(2)
    except KeyboardInterrupt:
        _graceful_shutdown()


if __name__ == "__main__":
    main()
