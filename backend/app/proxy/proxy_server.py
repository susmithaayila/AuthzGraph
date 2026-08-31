"""
AuthzGraph Local HTTP Proxy Interceptor
---------------------------------------
A lightweight asyncio TCP proxy that sits between your browser and the real API
server. It captures every HTTP request transparently and forwards it on, while
recording the method, path, host, and Authorization header for later BOLA/BFLA
scanning.

Usage:
  start_proxy()   → starts proxy on 0.0.0.0:8888 in a background thread
  stop_proxy()    → shuts the proxy down
  clear_captured() → empties the captured endpoint list

Configure your browser:
  HTTP Proxy: 127.0.0.1   Port: 8888

HTTPS: CONNECT tunneling is supported (connection forwarded but not decrypted).
"""

import asyncio
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

PROXY_PORT = 8888

# ── Shared state ────────────────────────────────────────────────────────────
CAPTURED_ENDPOINTS: List[Dict] = []
_captured_keys: Set[str] = set()
PROXY_RUNNING: bool = False
_proxy_loop: Optional[asyncio.AbstractEventLoop] = None
_proxy_thread: Optional[threading.Thread] = None
_proxy_server_obj = None

# Timestamp of the last new capture (used for idle-detection auto-trigger)
LAST_CAPTURE_TIME: Optional[datetime] = None

# Optional callbacks invoked whenever a new endpoint is captured
on_new_capture_callbacks: List[Callable[[], None]] = []


# ── Pipe helper ──────────────────────────────────────────────────────────────
async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── Core connection handler ──────────────────────────────────────────────────
async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    global CAPTURED_ENDPOINTS, _captured_keys
    try:
        # --- Read request line ---
        raw_line = await asyncio.wait_for(reader.readline(), timeout=15.0)
        if not raw_line:
            return
        request_line = raw_line.decode("utf-8", errors="ignore").strip()
        parts = request_line.split(" ")
        if len(parts) < 2:
            return

        method = parts[0].upper()
        target = parts[1]
        http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        # --- Read headers ---
        headers: Dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="ignore")
            if ":" in decoded:
                k, _, v = decoded.partition(":")
                headers[k.strip().lower()] = v.strip()

        host_header = headers.get("host", "")
        authorization = headers.get("authorization", None)
        content_length = int(headers.get("content-length", 0))

        # --- Read body ---
        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(reader.read(min(content_length, 65536)), timeout=10.0)

        # ── HTTPS CONNECT tunnel ─────────────────────────────────────────────
        if method == "CONNECT":
            hp = target.rsplit(":", 1)
            rhost = hp[0]
            rport = int(hp[1]) if len(hp) > 1 else 443
            try:
                rr, rw = await asyncio.wait_for(
                    asyncio.open_connection(rhost, rport), timeout=10.0
                )
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await asyncio.gather(
                    _pipe(reader, rw),
                    _pipe(rr, writer),
                    return_exceptions=True,
                )
            except Exception:
                try:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    await writer.drain()
                except Exception:
                    pass
            return

        # ── HTTP request ─────────────────────────────────────────────────────
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme in ("http", "https"):
            rhost = parsed.hostname or host_header.split(":")[0]
            rport = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            rhost = host_header.split(":")[0]
            try:
                rport = int(host_header.split(":")[1]) if ":" in host_header else 80
            except ValueError:
                rport = 80
            path = target

        # Record endpoint (deduplicated by method + host + path-without-query)
        clean_path = path.split("?")[0]
        endpoint_key = f"{method}:{host_header}:{clean_path}"
        if endpoint_key not in _captured_keys:
            _captured_keys.add(endpoint_key)
            CAPTURED_ENDPOINTS.append({
                "method": method,
                "host": host_header,
                "path": clean_path,
                "full_path": path,
                "authorization": authorization,
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "has_body": content_length > 0,
            })
            # Update idle-detection timestamp and notify watchers
            global LAST_CAPTURE_TIME
            LAST_CAPTURE_TIME = datetime.now(timezone.utc)
            for cb in list(on_new_capture_callbacks):
                try:
                    cb()
                except Exception:
                    pass

        # Forward request to real server
        try:
            rr, rw = await asyncio.wait_for(
                asyncio.open_connection(rhost, rport), timeout=10.0
            )
            # Rewrite to relative URL
            fwd = f"{method} {path} {http_version}\r\n"
            fwd += f"Host: {host_header}\r\n"
            skip = {"proxy-connection", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization"}
            for k, v in headers.items():
                if k not in skip:
                    fwd += f"{k}: {v}\r\n"
            fwd += "Connection: close\r\n\r\n"

            rw.write(fwd.encode())
            if body:
                rw.write(body)
            await rw.drain()

            # Relay response directly (streaming)
            try:
                while True:
                    chunk = await asyncio.wait_for(rr.read(8192), timeout=5.0)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            except asyncio.TimeoutError:
                pass
            rw.close()
        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── Proxy lifecycle ──────────────────────────────────────────────────────────
async def _serve() -> None:
    global _proxy_server_obj, PROXY_RUNNING
    try:
        server = await asyncio.start_server(_handle_client, "0.0.0.0", PROXY_PORT)
        _proxy_server_obj = server
        PROXY_RUNNING = True
        async with server:
            await server.serve_forever()
    except Exception:
        pass
    finally:
        PROXY_RUNNING = False


def _thread_main() -> None:
    global _proxy_loop
    _proxy_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_proxy_loop)
    try:
        _proxy_loop.run_until_complete(_serve())
    except Exception:
        pass
    finally:
        try:
            _proxy_loop.close()
        except Exception:
            pass


def start_proxy() -> bool:
    """Starts the proxy in a background daemon thread. Returns True if started."""
    global _proxy_thread, PROXY_RUNNING
    if PROXY_RUNNING:
        return False
    _proxy_thread = threading.Thread(target=_thread_main, daemon=True, name="AuthzProxyServer")
    _proxy_thread.start()
    return True


def stop_proxy() -> bool:
    """Stops the proxy server."""
    global PROXY_RUNNING, _proxy_loop, _proxy_server_obj
    PROXY_RUNNING = False
    if _proxy_server_obj:
        try:
            if _proxy_loop and not _proxy_loop.is_closed():
                _proxy_loop.call_soon_threadsafe(_proxy_server_obj.close)
        except Exception:
            pass
    if _proxy_loop and not _proxy_loop.is_closed():
        try:
            _proxy_loop.call_soon_threadsafe(_proxy_loop.stop)
        except Exception:
            pass
    return True


def clear_captured() -> None:
    """Empties the captured endpoint list and resets the idle timer."""
    global CAPTURED_ENDPOINTS, _captured_keys, LAST_CAPTURE_TIME
    CAPTURED_ENDPOINTS = []
    _captured_keys = set()
    LAST_CAPTURE_TIME = None


def get_captured() -> List[Dict]:
    return list(CAPTURED_ENDPOINTS)
