"""
vAPI Target Adapter for AuthzGraph Cross-Application Validation.
vAPI (github.com/roottusk/vapi) is a lightweight Flask application with
documented BOLA/BFLA-style vulnerabilities, used as an independently-built
second target to validate cross-application generalizability.

LIMITATION: vAPI does not ship a machine-readable OpenAPI spec.
This adapter uses a hand-authored minimal spec (experiments/targets/vapi_openapi.json).
Full auto-discovery of undocumented targets is designated as future work.
"""
from typing import Dict, Any, List, Optional


class VAPIAdapter:
    """
    Target adapter for vAPI (github.com/roottusk/vapi).
    Provides the endpoint descriptor needed by cross_app_validation.py
    to run the same attack-vector logic used against RideX/SecureBank.
    """

    BASE_URL = "http://localhost:5000"

    # vAPI user credentials for the cross-app validation test
    # To run: first register two users via POST /api2/user, note their IDs and tokens
    # The adapter uses placeholder credentials that must be set up once vAPI is running.
    USER_A_TOKEN: Optional[str] = None  # Legitimate user (owner)
    USER_B_TOKEN: Optional[str] = None  # Attacker user
    USER_A_ID: Optional[int] = None     # Legitimate user's object ID
    USER_B_ID: Optional[int] = None     # Attacker user's object ID

    ENDPOINT_DESCRIPTORS: List[Dict[str, Any]] = [
        {
            "path": "/api2/user/{id}",
            "method": "GET",
            "vulnerability_class": "BOLA",
            "description": "vAPI2 user fetch — no ownership check, sequential IDs",
            "object_id_param": "id",
            "writable_fields": [],
            "admin_path": False,
            "detection_rule": "cross_user_200",
        },
        {
            "path": "/api6/user/dead",
            "method": "GET",
            "vulnerability_class": "BFLA",
            "description": "vAPI6 admin endpoint — no ADMIN role check",
            "object_id_param": None,
            "writable_fields": [],
            "admin_path": True,
            "detection_rule": "non_admin_200",
        },
    ]

    @classmethod
    def get_base_url(cls) -> str:
        return cls.BASE_URL

    @classmethod
    def get_endpoint_descriptors(cls) -> List[Dict[str, Any]]:
        return cls.ENDPOINT_DESCRIPTORS

    @classmethod
    def setup_test_users(cls, client, base_url: str) -> bool:
        """
        Register two test users in vAPI and retrieve their tokens and IDs.
        Returns True if setup succeeded, False otherwise.
        """
        import time
        ts = int(time.time())
        user_a_creds = {"username": f"authzgraph_user_a_{ts}", "password": "TestPass123!", "name": "AuthzGraph Test UserA"}
        user_b_creds = {"username": f"authzgraph_user_b_{ts}", "password": "TestPass123!", "name": "AuthzGraph Test UserB"}

        try:
            # Register user A
            r_a = client.post(f"{base_url}/api2/user", json=user_a_creds)
            if r_a.status_code not in (200, 201):
                return False
            data_a = r_a.json()
            cls.USER_A_ID = data_a.get("id") or data_a.get("user", {}).get("id")
            cls.USER_A_TOKEN = data_a.get("token") or data_a.get("user", {}).get("token")

            # Register user B
            r_b = client.post(f"{base_url}/api2/user", json=user_b_creds)
            if r_b.status_code not in (200, 201):
                return False
            data_b = r_b.json()
            cls.USER_B_ID = data_b.get("id") or data_b.get("user", {}).get("id")
            cls.USER_B_TOKEN = data_b.get("token") or data_b.get("user", {}).get("token")

            return cls.USER_A_ID is not None and cls.USER_B_ID is not None

        except Exception:
            return False
