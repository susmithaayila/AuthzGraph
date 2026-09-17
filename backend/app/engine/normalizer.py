import re
from typing import Any, Dict

VOLATILE_KEYS = {
    "timestamp", "created_at", "updated_at", "expires_at", "date",
    "request_id", "req_id", "nonce", "jwt", "token", "session_id",
    "etag", "cursor", "page_token", "time", "uptime"
}

class ResponseNormalizer:
    """Strips volatile JSON dynamic fields before computing differential response payload diffs."""

    @classmethod
    def normalize_payload(cls, data: Any) -> Any:
        if isinstance(data, dict):
            cleaned = {}
            for k, v in data.items():
                if k.lower() in VOLATILE_KEYS or any(vk in k.lower() for vk in ["timestamp", "created_at", "requestid"]):
                    cleaned[k] = "<BLINDED_VOLATILE_FIELD>"
                else:
                    cleaned[k] = cls.normalize_payload(v)
            return cleaned
        elif isinstance(data, list):
            return [cls.normalize_payload(item) for item in data]
        elif isinstance(data, str):
            # Blind ISO 8601 timestamps
            if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', data):
                return "<BLINDED_TIMESTAMP>"
            return data
        return data

    @classmethod
    def compute_diff(cls, original: Any, substituted: Any) -> Dict[str, Any]:
        norm_orig = cls.normalize_payload(original)
        norm_sub = cls.normalize_payload(substituted)

        return {
            "is_structural_match": isinstance(norm_sub, type(norm_orig)),
            "normalized_original": norm_orig,
            "normalized_substituted": norm_sub
        }
