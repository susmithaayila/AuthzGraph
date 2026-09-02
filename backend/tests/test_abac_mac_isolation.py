"""
Tests for Part B.2 of Phase 7: ABAC and MAC layer isolation.
These tests prove that:
  - Disabling ABAC does NOT bypass the BOLA check (isolation is clean)
  - Disabling MAC does NOT bypass the BOLA or RBAC check
  - Each layer independently and solely is responsible for the denial
    that its corresponding attack vector exploits.
"""
import pytest
from app.engine.authz_engine import CentralAuthorizationEngine, set_security_mode, MAC_LEVELS
from app.engine.bank_data import SYNTHETIC_USERS, SYNTHETIC_DOCUMENTS


@pytest.fixture(autouse=True)
def ensure_secure_mode():
    """All B.2 tests run in SECURE mode."""
    set_security_mode("secure")
    yield
    set_security_mode("secure")


def get_user(user_id: int):
    return SYNTHETIC_USERS[user_id]


def get_doc(doc_id: int):
    return SYNTHETIC_DOCUMENTS[doc_id]


# ABAC Tests

def test_abac_same_region_manager_allow():
    """South MANAGER reading South-region doc: RBAC+BOLA+ABAC pass -> ALLOW"""
    marcus = get_user(301)
    doc_503 = get_doc(503)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=marcus,
        action="READ",
        resource_type="DOCUMENT",
        resource_owner_id=doc_503["owner_id"],
        resource_attributes=doc_503,
        required_permission="AUDIT_READ",
        endpoint_path="/api/v1/bank/documents/503",
    )
    assert decision.decision == "ALLOW", f"Expected ALLOW, got DENY: {decision.reason}"


def test_abac_cross_region_manager_deny():
    """North MANAGER reading South-region doc: RBAC+BOLA pass, ABAC fails -> DENY"""
    diana = get_user(302)
    doc_506 = get_doc(506)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=diana,
        action="READ",
        resource_type="DOCUMENT",
        resource_owner_id=doc_506["owner_id"],
        resource_attributes=doc_506,
        required_permission="AUDIT_READ",
        endpoint_path="/api/v1/bank/documents/506",
    )
    assert decision.decision == "DENY", "Expected DENY (ABAC cross-region)"
    assert decision.policy == "ABAC", f"Expected ABAC policy, got {decision.policy}"


def test_abac_disabled_cross_region_allows():
    """Same cross-region request with ABAC disabled -> ALLOW (proves ABAC = 100% exposure)"""
    diana = get_user(302)
    doc_506 = get_doc(506)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=diana,
        action="READ",
        resource_type="DOCUMENT",
        resource_owner_id=doc_506["owner_id"],
        resource_attributes=doc_506,
        required_permission="AUDIT_READ",
        endpoint_path="/api/v1/bank/documents/506",
        disabled_layers=["ABAC"],
    )
    assert decision.decision == "ALLOW", f"Expected ALLOW when ABAC disabled, got: {decision.reason}"


def test_abac_disabled_does_not_bypass_bola():
    """ABAC disabled but BOLA still active: Alice reading Bob's profile -> DENY (BOLA)"""
    alice = get_user(101)
    bob = get_user(102)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=alice,
        action="READ",
        resource_type="USER_PROFILE",
        resource_owner_id=bob["id"],
        resource_attributes=bob,
        required_permission="PROFILE_READ_SELF",
        endpoint_path="/api/v1/bank/users/102",
        disabled_layers=["ABAC"],
    )
    assert decision.decision == "DENY", "BOLA should block cross-user read even when ABAC disabled"
    assert decision.policy == "BOLA_PROTECTION", f"Expected BOLA_PROTECTION, got {decision.policy}"


# MAC No-Read-Up Tests

def test_mac_read_up_violation_deny():
    """Alice (CONFIDENTIAL L3) reading SECRET doc owned by self (508, L4) -> DENY (MAC)"""
    alice = get_user(101)
    doc_508 = get_doc(508)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=alice,
        action="READ",
        resource_type="DOCUMENT",
        resource_owner_id=doc_508["owner_id"],
        resource_attributes=doc_508,
        required_permission="DOCUMENT_READ_OWN",
        endpoint_path="/api/v1/bank/documents/508",
    )
    assert decision.decision == "DENY", "MAC should block CONFIDENTIAL user from reading SECRET doc"
    assert decision.policy == "MAC", f"Expected MAC policy, got {decision.policy}"


def test_mac_disabled_read_up_allows():
    """Same SECRET doc (508) read with only MAC disabled -> ALLOW (clean isolation without BOLA hack)"""
    alice = get_user(101)
    doc_508 = get_doc(508)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=alice,
        action="READ",
        resource_type="DOCUMENT",
        resource_owner_id=doc_508["owner_id"],
        resource_attributes=doc_508,
        required_permission="DOCUMENT_READ_OWN",
        endpoint_path="/api/v1/bank/documents/508",
        disabled_layers=["MAC"],
    )
    assert decision.decision == "ALLOW", f"Expected ALLOW when MAC disabled, got: {decision.reason}"


def test_mac_disabled_does_not_bypass_abac():
    """MAC disabled, ABAC still active: North MANAGER reading South doc -> DENY (ABAC)"""
    diana = get_user(302)
    doc_506 = get_doc(506)
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=diana,
        action="READ",
        resource_type="DOCUMENT",
        resource_owner_id=doc_506["owner_id"],
        resource_attributes=doc_506,
        required_permission="DOCUMENT_READ_DEPARTMENT",
        endpoint_path="/api/v1/bank/documents/506",
        disabled_layers=["MAC"],
    )
    assert decision.decision == "DENY", "ABAC should still block cross-region when MAC is disabled"
    assert decision.policy == "ABAC", f"Expected ABAC policy, got {decision.policy}"


# MAC No-Write-Down (Star Property) Tests

def test_mac_write_down_violation_deny():
    """Admin (SECRET L4) downgrading SECRET doc (507) to PUBLIC -> DENY (MAC star property)"""
    admin = get_user(401)
    doc_507 = get_doc(507)
    attrs = {**doc_507, "target_classification": "PUBLIC"}
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=admin,
        action="UPDATE",
        resource_type="DOCUMENT",
        resource_owner_id=doc_507["owner_id"],
        resource_attributes=attrs,
        required_permission="ADMIN_DASHBOARD",
        endpoint_path="/api/v1/bank/documents/507/classify",
    )
    assert decision.decision == "DENY", "MAC write-down (star property) should block SECRET->PUBLIC"
    assert decision.policy == "MAC", f"Expected MAC policy, got {decision.policy}"
    assert "no_write_down" in str(decision.extra_details), "Expected no_write_down in extra_details"


def test_mac_write_down_disabled_allows():
    """Same write-down attempt with MAC disabled -> ALLOW"""
    admin = get_user(401)
    doc_507 = get_doc(507)
    attrs = {**doc_507, "target_classification": "PUBLIC"}
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=admin,
        action="UPDATE",
        resource_type="DOCUMENT",
        resource_owner_id=doc_507["owner_id"],
        resource_attributes=attrs,
        required_permission="ADMIN_DASHBOARD",
        endpoint_path="/api/v1/bank/documents/507/classify",
        disabled_layers=["MAC"],
    )
    assert decision.decision == "ALLOW", f"Expected ALLOW when MAC disabled (write-down), got: {decision.reason}"


def test_mac_same_level_write_is_allowed():
    """Admin keeping SECRET doc at SECRET (no downgrade) -> ALLOW"""
    admin = get_user(401)
    doc_507 = get_doc(507)
    attrs = {**doc_507, "target_classification": "SECRET"}
    decision = CentralAuthorizationEngine.evaluate_request(
        current_user=admin,
        action="UPDATE",
        resource_type="DOCUMENT",
        resource_owner_id=doc_507["owner_id"],
        resource_attributes=attrs,
        required_permission="ADMIN_DASHBOARD",
        endpoint_path="/api/v1/bank/documents/507/classify",
    )
    assert decision.decision == "ALLOW", f"Expected ALLOW for same-level write, got: {decision.reason}"


# HTTP Route Integration Isolation Tests

def test_http_abac_isolation_via_api():
    """
    HTTP integration test:
    North MANAGER (token_manager_north) accessing /bank/documents/506
    - With ABAC active -> DENY (403)
    - With ABAC disabled -> ALLOW (200)
    Proves ABAC layer isolation over HTTP.
    """
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    headers = {"Authorization": "Bearer token_manager_north"}

    # Ensure secure mode & all layers active
    client.post("/api/v1/policy/mode", json={"mode": "secure"})
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})

    r_active = client.get("/api/v1/bank/documents/506", headers=headers)
    assert r_active.status_code == 403, f"Expected 403 DENY with ABAC active, got {r_active.status_code}"
    assert r_active.json().get("detail", {}).get("policy") == "ABAC"

    # Disable ABAC
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "MAC", "AuthN"]})
    r_disabled = client.get("/api/v1/bank/documents/506", headers=headers)
    assert r_disabled.status_code == 200, f"Expected 200 ALLOW with ABAC disabled, got {r_disabled.status_code}"

    # Reset
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})


def test_http_mac_read_up_isolation_via_api():
    """
    HTTP integration test:
    Alice (token_alice) accessing /bank/documents/508 (SECRET doc owned by Alice)
    - With MAC active -> DENY (403)
    - With MAC disabled -> ALLOW (200)
    Proves MAC No-Read-Up layer isolation over HTTP.
    """
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    headers = {"Authorization": "Bearer token_alice"}

    client.post("/api/v1/policy/mode", json={"mode": "secure"})
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})

    r_active = client.get("/api/v1/bank/documents/508", headers=headers)
    assert r_active.status_code == 403, f"Expected 403 DENY with MAC active, got {r_active.status_code}"
    assert r_active.json().get("detail", {}).get("policy") == "MAC"

    # Disable MAC
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "AuthN"]})
    r_disabled = client.get("/api/v1/bank/documents/508", headers=headers)
    assert r_disabled.status_code == 200, f"Expected 200 ALLOW with MAC disabled, got {r_disabled.status_code}"

    # Reset
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})


def test_rbac_isolation_deny_and_allow():
    """
    Engine unit test:
    Alice (CUSTOMER) requesting AUDIT_READ on /bank/audit-summary:
    - With RBAC active -> DENY (policy="RBAC")
    - With RBAC disabled -> ALLOW
    Proves RBAC permission matrix layer isolation.
    """
    alice = get_user(101)
    d_active = CentralAuthorizationEngine.evaluate_request(
        current_user=alice,
        action="READ",
        resource_type="AUDIT_SUMMARY",
        resource_owner_id=None,
        resource_attributes={},
        required_permission="AUDIT_READ",
        endpoint_path="/api/v1/bank/audit-summary",
    )
    assert d_active.decision == "DENY"
    assert d_active.policy == "RBAC"

    d_disabled = CentralAuthorizationEngine.evaluate_request(
        current_user=alice,
        action="READ",
        resource_type="AUDIT_SUMMARY",
        resource_owner_id=None,
        resource_attributes={},
        required_permission="AUDIT_READ",
        endpoint_path="/api/v1/bank/audit-summary",
        disabled_layers=["RBAC"],
    )
    assert d_disabled.decision == "ALLOW"


def test_http_rbac_isolation_via_api():
    """
    HTTP integration test:
    Alice (token_alice) accessing /bank/audit-summary
    - With RBAC active -> DENY (403)
    - With RBAC disabled -> ALLOW (200)
    Proves RBAC layer isolation over HTTP.
    """
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    headers = {"Authorization": "Bearer token_alice"}

    client.post("/api/v1/policy/mode", json={"mode": "secure"})
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})

    r_active = client.get("/api/v1/bank/audit-summary", headers=headers)
    assert r_active.status_code == 403, f"Expected 403 DENY with RBAC active, got {r_active.status_code}"
    assert r_active.json().get("detail", {}).get("policy") == "RBAC"

    # Disable RBAC
    client.post("/api/v1/policy/active-layers", json={"layers": ["BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})
    r_disabled = client.get("/api/v1/bank/audit-summary", headers=headers)
    assert r_disabled.status_code == 200, f"Expected 200 ALLOW with RBAC disabled, got {r_disabled.status_code}"

    # Reset
    client.post("/api/v1/policy/active-layers", json={"layers": ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]})


