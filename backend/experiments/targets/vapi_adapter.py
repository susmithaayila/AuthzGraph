"""
vAPI Target Adapter for AuthzGraph Cross-Application Validation.
vAPI (github.com/roottusk/vapi) is an independently-built vulnerable REST API
used as a second target to validate cross-application generalizability.

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
    USER_A_TOKEN: Optional[str] = None  # Legitimate user (owner)
    USER_B_TOKEN: Optional[str] = None  # Attacker user
    USER_A_ID: Optional[int] = None     # Legitimate user's object ID
    USER_B_ID: Optional[int] = None     # Attacker user's object ID

    ENDPOINT_DESCRIPTORS: List[Dict[str, Any]] = [
        {
            "path": "/api1/user/{id}",
            "method": "GET",
            "vulnerability_class": "BOLA",
            "description": "vAPI1 user fetch — no ownership check, sequential IDs",
            "object_id_param": "id",
            "writable_fields": [],
            "admin_path": False,
            "detection_rule": "cross_user_200",
        },
        {
            "path": "/api5/users",
            "method": "GET",
            "vulnerability_class": "BFLA",
            "description": "vAPI5 all users fetch — returns all users without admin privilege verification",
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
        # synthetic test credential
        user_a_creds = {"username": f"authzgraph_user_a_{ts}", "password": "TestPass123!", "name": "AuthzGraph Test UserA"}
        # synthetic test credential
        user_b_creds = {"username": f"authzgraph_user_b_{ts}", "password": "TestPass123!", "name": "AuthzGraph Test UserB"}

        # Try without /vapi and with /vapi prefix
        for prefix in ["", "/vapi"]:
            try:
                # Register user A via API1
                r_a = client.post(f"{base_url}{prefix}/api1/user", json=user_a_creds)
                if r_a.status_code in (200, 201):
                    data_a = r_a.json()
                    cls.USER_A_ID = data_a.get("id") or data_a.get("user", {}).get("id")
                    cls.USER_A_TOKEN = data_a.get("token") or data_a.get("user", {}).get("token") or "token_user_a"

                    # Register user B via API1
                    r_b = client.post(f"{base_url}{prefix}/api1/user", json=user_b_creds)
                    if r_b.status_code in (200, 201):
                        data_b = r_b.json()
                        cls.USER_B_ID = data_b.get("id") or data_b.get("user", {}).get("id")
                        cls.USER_B_TOKEN = data_b.get("token") or data_b.get("user", {}).get("token") or "token_user_b"

                    if cls.USER_A_ID is not None and cls.USER_B_ID is not None:
                        return True
            except Exception:
                continue

        return False
