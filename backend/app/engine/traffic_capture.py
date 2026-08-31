"""
Traffic Capture Engine for AuthzGraph Attacker Console.
Maintains in-memory network trace logs simulating raw proxy/DevTools packet capture.
100% Synthetic local data logging only.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

NETWORK_TRACE_LOG: List[Dict[str, Any]] = []


def record_traffic(
    method: str,
    path: str,
    full_url: str,
    headers: Dict[str, str],
    body: Optional[Any] = None,
    response_status: int = 200,
    response_body: Optional[Any] = None,
    caller_user_id: Optional[Any] = None,
) -> Dict[str, Any]:
    global NETWORK_TRACE_LOG

    packet = {
        "request_id": f"req_{uuid.uuid4().hex[:8]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": method.upper(),
        "path": path,
        "full_url": full_url,
        "request_headers": headers,
        "request_body": body,
        "response_status": response_status,
        "response_body": response_body,
        "caller_user_id": caller_user_id,
    }

    NETWORK_TRACE_LOG.insert(0, packet)
    if len(NETWORK_TRACE_LOG) > 200:
        NETWORK_TRACE_LOG = NETWORK_TRACE_LOG[:200]

    return packet


def get_captured_traffic(caller_user_id: Optional[Any] = None, limit: int = 10) -> List[Dict[str, Any]]:
    if caller_user_id is None:
        return NETWORK_TRACE_LOG[:limit]

    user_id_str = str(caller_user_id)
    filtered = [
        pkt for pkt in NETWORK_TRACE_LOG
        if pkt.get("caller_user_id") is not None and str(pkt.get("caller_user_id")) == user_id_str
    ]
    
    # If no filtered packets match yet, return recent packets as fallback for demo fluidity
    if not filtered:
        return NETWORK_TRACE_LOG[:limit]

    return filtered[:limit]


def clear_captured_traffic():
    global NETWORK_TRACE_LOG
    NETWORK_TRACE_LOG = []
