"""
Automated Pytest Suite for AuthzGraph — SecureBank Authorization Engine & Endpoints.
Verifies BOLA, BOPLA, BFLA, RBAC, ABAC, MAC in both Vulnerable Mode and Secure Mode.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from main import app
from app.engine.authz_engine import set_security_mode, get_security_mode
from app.engine.bank_data import reset_synthetic_data

client = TestClient(app)


def setup_function():
    set_security_mode("secure")
    reset_synthetic_data()


# ── BOLA Tests ──────────────────────────────────────────────────────────────
def test_bola_vulnerable_mode():
    set_security_mode("vulnerable")
    # Alice (101) accessing Bob's profile (102) in Vulnerable Mode -> 200 OK
    res = client.get("/api/v1/bank/users/102", headers={"Authorization": "Bearer token_alice"})
    assert res.status_code == 200
    data = res.json()
    assert data["data"]["name"] == "Bob Smith"
    assert data["mode"] == "vulnerable"


def test_bola_secure_mode():
    set_security_mode("secure")
    # Alice (101) accessing Bob's profile (102) in Secure Mode -> 403 Forbidden
    res = client.get("/api/v1/bank/users/102", headers={"Authorization": "Bearer token_alice"})
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert "Access Denied" in detail["error"]
    assert "BOLA Protection" in detail["reason"]

    # Alice accessing her own profile (101) -> 200 OK
    res_own = client.get("/api/v1/bank/users/101", headers={"Authorization": "Bearer token_alice"})
    assert res_own.status_code == 200
    assert res_own.json()["data"]["name"] == "Alice Johnson"


# ── BOPLA Tests ─────────────────────────────────────────────────────────────
def test_bopla_vulnerable_mode():
    set_security_mode("vulnerable")
    # Alice attempts to alter privileged fields (role='ADMIN', accountBalance=999999)
    payload = {"role": "ADMIN", "accountBalance": 999999.0}
    res = client.patch("/api/v1/bank/users/101", json=payload, headers={"Authorization": "Bearer token_alice"})
    assert res.status_code == 200
    assert res.json()["updated_user"]["role"] == "ADMIN"


def test_bopla_secure_mode():
    set_security_mode("secure")
    # Alice attempts to alter privileged fields -> 403 Forbidden
    payload = {"role": "ADMIN", "accountBalance": 999999.0}
    res = client.patch("/api/v1/bank/users/101", json=payload, headers={"Authorization": "Bearer token_alice"})
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert "Property Update Blocked" in detail["error"]
    assert "BOPLA Protection" in detail["reason"]

    # Alice updating safe fields (phone) -> 200 OK
    safe_payload = {"phone": "+1-555-9999"}
    res_safe = client.patch("/api/v1/bank/users/101", json=safe_payload, headers={"Authorization": "Bearer token_alice"})
    assert res_safe.status_code == 200


# ── BFLA Tests ─────────────────────────────────────────────────────────────
def test_bfla_vulnerable_mode():
    set_security_mode("vulnerable")
    # Customer Alice calling Admin endpoint -> 200 OK in Vulnerable Mode
    res = client.get("/api/v1/bank/admin/users", headers={"Authorization": "Bearer token_alice"})
    assert res.status_code == 200
    assert "users" in res.json()


def test_bfla_secure_mode():
    set_security_mode("secure")
    # Customer Alice calling Admin endpoint -> 403 Forbidden in Secure Mode
    res = client.get("/api/v1/bank/admin/users", headers={"Authorization": "Bearer token_alice"})
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert "Administrator Privileges Required" in detail["error"]

    # Admin calling Admin endpoint -> 200 OK
    res_admin = client.get("/api/v1/bank/admin/users", headers={"Authorization": "Bearer token_admin"})
    assert res_admin.status_code == 200
    assert len(res_admin.json()["users"]) >= 10


# ── Multi-User BOLA Exposure Lab Test ───────────────────────────────────────
def test_bola_exposure_lab():
    set_security_mode("vulnerable")
    res_vuln = client.get("/api/v1/bank/demo/bola/users", headers={"Authorization": "Bearer token_alice"})
    assert res_vuln.status_code == 200
    assert res_vuln.json()["unauthorized_accessible_objects"] == 9

    set_security_mode("secure")
    res_sec = client.get("/api/v1/bank/demo/bola/users", headers={"Authorization": "Bearer token_alice"})
    assert res_sec.status_code == 200
    assert res_sec.json()["unauthorized_accessible_objects"] == 0


# ── Simulators Tests (RBAC, ABAC, MAC) ──────────────────────────────────────
def test_rbac_simulator():
    res = client.post("/api/v1/bank/simulator/rbac", json={
        "user_id": 101,
        "requested_action": "View All Customers",
        "required_permission": "CUSTOMER_READ_ALL"
    })
    assert res.status_code == 200
    assert res.json()["decision"] == "DENY"

    res_admin = client.post("/api/v1/bank/simulator/rbac", json={
        "user_id": 401,
        "requested_action": "View All Customers",
        "required_permission": "CUSTOMER_READ_ALL"
    })
    assert res_admin.status_code == 200
    assert res_admin.json()["decision"] == "ALLOW"


def test_mac_simulator():
    # User 101 clearance = CONFIDENTIAL (lvl 3), Doc 504 classification = SECRET (lvl 4) -> DENY
    res_deny = client.post("/api/v1/bank/simulator/mac", json={"user_id": 101, "doc_id": 504})
    assert res_deny.status_code == 200
    assert res_deny.json()["decision"] == "DENY"

    # User 401 clearance = SECRET (lvl 4), Doc 504 classification = SECRET (lvl 4) -> ALLOW
    res_allow = client.post("/api/v1/bank/simulator/mac", json={"user_id": 401, "doc_id": 504})
    assert res_allow.status_code == 200
    assert res_allow.json()["decision"] == "ALLOW"



# ── Phase 6 Attacker Console Endpoints Tests ─────────────────────────────────
def test_phase6_traffic_capture():
    res = client.get("/api/v1/bank/demo/traffic-capture?user_id=101&limit=5")
    assert res.status_code == 200
    assert "packets" in res.json()


def test_phase6_replay_vulnerable_and_secure():
    # Vulnerable mode: Replay /api/v1/bank/users/102 as Alice -> 200 OK
    set_security_mode("vulnerable")
    res_vuln = client.post("/api/v1/bank/demo/replay", json={
        "method": "GET",
        "path": "/api/v1/bank/users/102",
        "headers": {"Authorization": "Bearer token_alice"},
        "caller_id": 101
    })
    assert res_vuln.status_code == 200
    assert res_vuln.json()["status_code"] == 200
    assert res_vuln.json()["decision"] == "ALLOW"

    # Secure mode: Replay same request -> 403 Forbidden
    set_security_mode("secure")
    res_sec = client.post("/api/v1/bank/demo/replay", json={
        "method": "GET",
        "path": "/api/v1/bank/users/102",
        "headers": {"Authorization": "Bearer token_alice"},
        "caller_id": 101
    })
    assert res_sec.status_code == 200
    assert res_sec.json()["status_code"] == 403
    assert res_sec.json()["decision"] == "DENY"


def test_phase6_enumeration_vulnerable_and_secure():
    # Vulnerable mode enumeration -> 9 exposed
    set_security_mode("vulnerable")
    res_vuln = client.post("/api/v1/bank/demo/enumerate", json={
        "vulnerability_type": "BOLA",
        "start_id": 101,
        "end_id": 110,
        "caller_id": 101
    })
    assert res_vuln.status_code == 200
    assert res_vuln.json()["total_exposed"] == 9

    # Secure mode enumeration -> 0 exposed
    set_security_mode("secure")
    res_sec = client.post("/api/v1/bank/demo/enumerate", json={
        "vulnerability_type": "BOLA",
        "start_id": 101,
        "end_id": 110,
        "caller_id": 101
    })
    assert res_sec.status_code == 200
    assert res_sec.json()["total_exposed"] == 0


def test_phase6_token_inspector():
    res = client.get("/api/v1/bank/demo/token-inspector?token=token_alice")
    assert res.status_code == 200
    data = res.json()
    assert data["user_resolved"] == "Alice Johnson"
    assert len(data["security_findings"]) > 0
    assert data["security_findings"][0]["vulnerability_class"] == "OWASP API2:2023 Broken Authentication"

