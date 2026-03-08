"""
SentinelGate - Windows System Proxy Manager
Manages the OS-level proxy settings so ALL outbound HTTP/HTTPS traffic
(from browsers, desktop apps, etc.) flows through SentinelGate's proxy.

Uses the Windows Registry to modify Internet Settings.
"""

import winreg
import ctypes
import subprocess
import os
import sys
import atexit
import signal

# Registry path for Internet proxy settings
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Proxy config
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8081  # mitmproxy will listen here

# Domains to bypass (localhost and local network)
BYPASS_LIST = "localhost;127.*;10.*;192.168.*;*.local;<local>"


def _notify_system_proxy_changed():
    """
    Notify Windows that Internet Settings have changed.
    This forces all apps to pick up the new proxy configuration immediately.
    """
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
    internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)


def get_current_proxy_settings():
    """Read current proxy settings from the registry."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                enabled = 0
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                server = ""
            try:
                override, _ = winreg.QueryValueEx(key, "ProxyOverride")
            except FileNotFoundError:
                override = ""
            return {
                "enabled": bool(enabled),
                "server": server,
                "override": override,
            }
    except Exception as e:
        print(f"[ProxyManager] Error reading proxy settings: {e}")
        return {"enabled": False, "server": "", "override": ""}


def _backup_proxy_settings():
    """Save current proxy settings so we can restore them on exit."""
    return get_current_proxy_settings()


def enable_system_proxy():
    """
    Enable the system-wide proxy pointing to SentinelGate.
    All HTTP/HTTPS traffic from every app will flow through our proxy.
    """
    proxy_address = f"{PROXY_HOST}:{PROXY_PORT}"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_address)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, BYPASS_LIST)

        _notify_system_proxy_changed()
        print(f"[ProxyManager] ✅ System proxy ENABLED → {proxy_address}")
        print(f"[ProxyManager]    Bypass list: {BYPASS_LIST}")
        return True
    except Exception as e:
        print(f"[ProxyManager] ❌ Failed to enable system proxy: {e}")
        return False


def disable_system_proxy():
    """
    Disable the system-wide proxy and restore normal connectivity.
    """
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

        _notify_system_proxy_changed()
        print("[ProxyManager] 🔓 System proxy DISABLED — normal connectivity restored")
        return True
    except Exception as e:
        print(f"[ProxyManager] ❌ Failed to disable system proxy: {e}")
        return False


def restore_proxy_settings(backup: dict):
    """Restore proxy settings from a backup."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(
                key, "ProxyEnable", 0, winreg.REG_DWORD, int(backup.get("enabled", 0))
            )
            winreg.SetValueEx(
                key, "ProxyServer", 0, winreg.REG_SZ, backup.get("server", "")
            )
            winreg.SetValueEx(
                key, "ProxyOverride", 0, winreg.REG_SZ, backup.get("override", "")
            )

        _notify_system_proxy_changed()
        print("[ProxyManager] 🔄 Proxy settings restored to original values")
        return True
    except Exception as e:
        print(f"[ProxyManager] ❌ Failed to restore proxy settings: {e}")
        return False


def is_proxy_active():
    """Check if our SentinelGate proxy is currently the active system proxy."""
    settings = get_current_proxy_settings()
    expected = f"{PROXY_HOST}:{PROXY_PORT}"
    return settings["enabled"] and settings["server"] == expected


def install_mitmproxy_ca():
    """
    Install the mitmproxy CA certificate into the Windows certificate store.
    This is required so HTTPS interception works without certificate errors.
    Returns True if successful.
    """
    # mitmproxy stores its CA cert here after first run
    ca_cert_path = os.path.expanduser(r"~\.mitmproxy\mitmproxy-ca-cert.cer")
    
    if not os.path.exists(ca_cert_path):
        print(f"[ProxyManager] CA certificate not found at {ca_cert_path}")
        print("[ProxyManager] It will be generated on first proxy run.")
        return False
    
    try:
        # Install the CA cert into the Windows Root store
        result = subprocess.run(
            ["certutil", "-addstore", "-user", "Root", ca_cert_path],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("[ProxyManager] ✅ mitmproxy CA certificate installed in Windows trust store")
            return True
        else:
            print(f"[ProxyManager] ⚠️ certutil output: {result.stderr}")
            return False
    except Exception as e:
        print(f"[ProxyManager] ❌ Failed to install CA certificate: {e}")
        return False


def is_ca_installed():
    """Check if the mitmproxy CA certificate is already installed."""
    ca_cert_path = os.path.expanduser(r"~\.mitmproxy\mitmproxy-ca-cert.cer")
    return os.path.exists(ca_cert_path)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SentinelGate Proxy Manager")
    parser.add_argument("action", choices=["enable", "disable", "status", "install-ca"])
    args = parser.parse_args()

    if args.action == "enable":
        enable_system_proxy()
    elif args.action == "disable":
        disable_system_proxy()
    elif args.action == "status":
        settings = get_current_proxy_settings()
        active = is_proxy_active()
        print(f"  Proxy Enabled:  {settings['enabled']}")
        print(f"  Proxy Server:   {settings['server']}")
        print(f"  Bypass List:    {settings['override']}")
        print(f"  SentinelGate:   {'✅ ACTIVE' if active else '❌ Not active'}")
    elif args.action == "install-ca":
        install_mitmproxy_ca()
