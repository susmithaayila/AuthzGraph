"""
Windows System Proxy Manager
-----------------------------
Automatically sets / clears the Windows system-wide HTTP proxy via the
registry so Chrome, Edge, and all system-aware apps route through the
AuthzGraph interceptor without any manual browser configuration.

Note: Firefox uses its own proxy settings and is NOT affected by this.
"""

import sys
import ctypes

_PROXY_SAVED_ENABLE: int | None = None
_PROXY_SAVED_SERVER: str | None = None
_PROXY_SAVED_OVERRIDE: str | None = None

# Wininet constants
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37

_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# Bypass list — AuthzGraph backend on port 8000 bypasses the proxy so UI calls stay direct,
# while target app traffic on port 8080 is routed into proxy via <-loopback>.
_PROXY_BYPASS = "127.0.0.1:8000;localhost:8000;<-loopback>"


def _get_winreg():
    if sys.platform != "win32":
        return None
    import winreg  # noqa: PLC0415
    return winreg


def enable(host: str = "127.0.0.1", port: int = 8888) -> bool:
    """
    Enable the Windows system proxy pointing to host:port.
    Saves the previous state so it can be restored via disable().
    Returns True on success.
    """
    global _PROXY_SAVED_ENABLE, _PROXY_SAVED_SERVER, _PROXY_SAVED_OVERRIDE
    winreg = _get_winreg()
    if winreg is None:
        return False  # Not on Windows
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            _REG_PATH,
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        )
        # Save current state
        try:
            _PROXY_SAVED_ENABLE, _ = winreg.QueryValueEx(key, "ProxyEnable")
        except FileNotFoundError:
            _PROXY_SAVED_ENABLE = 0
        try:
            _PROXY_SAVED_SERVER, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            _PROXY_SAVED_SERVER = ""
        try:
            _PROXY_SAVED_OVERRIDE, _ = winreg.QueryValueEx(key, "ProxyOverride")
        except FileNotFoundError:
            _PROXY_SAVED_OVERRIDE = ""

        # Set new proxy
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, _PROXY_BYPASS)
        winreg.CloseKey(key)
        _notify_windows()
        return True
    except Exception:
        return False


def disable() -> bool:
    """
    Restore the Windows system proxy to whatever it was before enable() was called.
    Returns True on success.
    """
    global _PROXY_SAVED_ENABLE, _PROXY_SAVED_SERVER, _PROXY_SAVED_OVERRIDE
    winreg = _get_winreg()
    if winreg is None:
        return False
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            _REG_PATH,
            0,
            winreg.KEY_WRITE,
        )
        restore_enable = _PROXY_SAVED_ENABLE if _PROXY_SAVED_ENABLE is not None else 0
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, restore_enable)
        if _PROXY_SAVED_SERVER is not None:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, _PROXY_SAVED_SERVER)
        if _PROXY_SAVED_OVERRIDE is not None:
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, _PROXY_SAVED_OVERRIDE)
        winreg.CloseKey(key)
        _notify_windows()
        _PROXY_SAVED_ENABLE = None
        _PROXY_SAVED_SERVER = None
        _PROXY_SAVED_OVERRIDE = None
        return True
    except Exception:
        return False


def _notify_windows() -> None:
    """Tell Windows (and Chrome/Edge) that proxy settings have changed."""
    try:
        wininet = ctypes.windll.Wininet  # type: ignore[attr-defined]
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass
