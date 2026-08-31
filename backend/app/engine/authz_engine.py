"""
Central Unified Authorization Engine for SecureBank Demo Platform.
Evaluates Authentication, RBAC, ABAC, MAC, Object Ownership (BOLA),
Property Schemas (BOPLA), and Function Boundaries (BFLA).
"""
import copy
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from app.engine.bank_data import SYNTHETIC_USERS, TOKEN_MAP

# ─────────────────────────────────────────────────────────────────────────────
# Global Application Security Mode (Toggleable via UI or API)
# ─────────────────────────────────────────────────────────────────────────────
CURRENT_SECURITY_MODE = "vulnerable"  # "vulnerable" | "secure"


def set_security_mode(mode: str) -> str:
    global CURRENT_SECURITY_MODE
    if mode.lower() in ("vulnerable", "vulnerable_mode", "vun"):
        CURRENT_SECURITY_MODE = "vulnerable"
    elif mode.lower() in ("secure", "secure_mode", "sec"):
        CURRENT_SECURITY_MODE = "secure"
    return CURRENT_SECURITY_MODE


def get_security_mode() -> str:
    return CURRENT_SECURITY_MODE


# ─────────────────────────────────────────────────────────────────────────────
# Security Clearance & Classification Lattice (MAC Model)
# ─────────────────────────────────────────────────────────────────────────────
MAC_LEVELS: Dict[str, int] = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "SECRET": 4,
}


# ─────────────────────────────────────────────────────────────────────────────
# RBAC Matrix & Role Permissions
# ─────────────────────────────────────────────────────────────────────────────
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "CUSTOMER": [
        "PROFILE_READ_SELF",
        "PROFILE_UPDATE_SELF",
        "ACCOUNT_READ_SELF",
        "TRANSACTION_READ_SELF",
        "DOCUMENT_READ_OWN",
        "TICKET_READ_OWN",
    ],
    "SUPPORT": [
        "PROFILE_READ_SELF",
        "PROFILE_UPDATE_SELF",
        "ACCOUNT_READ_SELF",
        "TRANSACTION_READ_SELF",
        "TICKET_READ_ASSIGNED",
        "TICKET_UPDATE_ASSIGNED",
    ],
    "MANAGER": [
        "PROFILE_READ_SELF",
        "PROFILE_UPDATE_SELF",
        "ACCOUNT_READ_SELF",
        "TRANSACTION_READ_SELF",
        "CUSTOMER_READ_DEPARTMENT",
        "CUSTOMER_CREATE",
        "AUDIT_READ",
        "DOCUMENT_READ_DEPARTMENT",
        "TICKET_READ_DEPARTMENT",
    ],
    "ADMIN": [
        "PROFILE_READ_SELF",
        "PROFILE_UPDATE_SELF",
        "ACCOUNT_READ_SELF",
        "TRANSACTION_READ_SELF",
        "CUSTOMER_READ_ALL",
        "CUSTOMER_CREATE",
        "CUSTOMER_DELETE",
        "ROLE_MODIFY",
        "AUDIT_READ",
        "ADMIN_DASHBOARD",
        "DOCUMENT_READ_ALL",
        "TICKET_READ_ALL",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# BOPLA Privileged Field Definitions (Fields users cannot self-update)
# ─────────────────────────────────────────────────────────────────────────────
PRIVILEGED_PROPERTIES = {
    "role",
    "accountBalance",
    "balance",
    "internalRiskScore",
    "isVerified",
    "clearance",
    "clearance_level",
    "department",
}

SAFE_CUSTOMER_PROPERTIES = {
    "name",
    "phone",
    "email",
    "address",
}


# ─────────────────────────────────────────────────────────────────────────────
# Structured Decision Model & Audit Log Storage
# ─────────────────────────────────────────────────────────────────────────────
class AuthorizationDecision:
    def __init__(
        self,
        decision: str,  # "ALLOW" | "DENY"
        reason: str,
        policy: str,    # "AUTHENTICATION" | "BOLA_PROTECTION" | "BOPLA_PROTECTION" | "BFLA_PROTECTION" | "RBAC" | "ABAC" | "MAC"
        required_permission: Optional[str] = None,
        user_role: Optional[str] = None,
        user_id: Optional[Any] = None,
        username: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: int = 200,
        mode: Optional[str] = None,
        extra_details: Optional[Dict[str, Any]] = None,
    ):
        self.decision = decision
        self.reason = reason
        self.policy = policy
        self.required_permission = required_permission
        self.user_role = user_role
        self.user_id = user_id
        self.username = username
        self.endpoint = endpoint
        self.status_code = status_code
        self.mode = mode or CURRENT_SECURITY_MODE
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.extra_details = extra_details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "policy": self.policy,
            "required_permission": self.required_permission,
            "user_role": self.user_role,
            "user_id": self.user_id,
            "username": self.username,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "mode": self.mode,
            "timestamp": self.timestamp,
            "extra_details": self.extra_details,
        }


SECURITY_DECISION_LOGS: List[Dict[str, Any]] = []


def log_decision(decision: AuthorizationDecision):
    global SECURITY_DECISION_LOGS
    SECURITY_DECISION_LOGS.insert(0, decision.to_dict())
    # Keep last 500 entries
    if len(SECURITY_DECISION_LOGS) > 500:
        SECURITY_DECISION_LOGS = SECURITY_DECISION_LOGS[:500]


def get_decision_logs(limit: int = 100) -> List[Dict[str, Any]]:
    return SECURITY_DECISION_LOGS[:limit]


def clear_decision_logs():
    global SECURITY_DECISION_LOGS
    SECURITY_DECISION_LOGS = []


# ─────────────────────────────────────────────────────────────────────────────
# Helper to resolve user from Bearer Token or User ID
# ─────────────────────────────────────────────────────────────────────────────
def resolve_user_from_token_or_header(token_or_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token_or_id:
        return None

    clean = token_or_id.replace("Bearer ", "").strip()
    if clean in TOKEN_MAP:
        return TOKEN_MAP[clean]

    # Check if raw integer ID passed
    if clean.isdigit():
        uid = int(clean)
        if uid in SYNTHETIC_USERS:
            return SYNTHETIC_USERS[uid]

    # Check if string starts with "token_"
    if not clean.startswith("token_"):
        alt = f"token_{clean}"
        if alt in TOKEN_MAP:
            return TOKEN_MAP[alt]

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Unified Authorization Engine Evaluator
# ─────────────────────────────────────────────────────────────────────────────
class CentralAuthorizationEngine:
    """
    Evaluates requests against Authentication, RBAC, ABAC, MAC, BOLA, BOPLA, and BFLA rules.
    In VULNERABLE mode, authorization checks are bypassed to demonstrate security vulnerabilities.
    In SECURE mode, full complete mediation is enforced.
    """

    @classmethod
    def evaluate_request(
        cls,
        current_user: Optional[Dict[str, Any]],
        action: str,  # "READ" | "UPDATE" | "DELETE" | "EXECUTE"
        resource_type: str,  # "USER_PROFILE" | "ACCOUNT" | "TRANSACTION" | "DOCUMENT" | "SUPPORT_TICKET" | "ADMIN_FUNCTION"
        resource_owner_id: Optional[Any] = None,
        resource_attributes: Optional[Dict[str, Any]] = None,
        requested_properties: Optional[List[str]] = None,
        required_permission: Optional[str] = None,
        endpoint_path: Optional[str] = None,
    ) -> AuthorizationDecision:
        resource_attributes = resource_attributes or {}
        mode = get_security_mode()

        # Step 1: Authentication Check
        if not current_user:
            decision = AuthorizationDecision(
                decision="DENY",
                reason="Authentication required. Unauthenticated request.",
                policy="AUTHENTICATION",
                status_code=401,
                endpoint=endpoint_path,
            )
            log_decision(decision)
            return decision

        user_id = current_user.get("id")
        user_role = current_user.get("role", "CUSTOMER")
        username = current_user.get("name", "Unknown User")
        user_clearance = current_user.get("clearance", "PUBLIC")
        user_clearance_lvl = MAC_LEVELS.get(user_clearance.upper(), 1)
        user_dept = current_user.get("department", "")
        user_region = current_user.get("region", "")

        # IF VULNERABLE MODE: Demonstrate authorization failure (Bypass checks!)
        if mode == "vulnerable":
            decision = AuthorizationDecision(
                decision="ALLOW",
                reason=f"⚠️ VULNERABLE MODE: Authorization check bypassed on {endpoint_path or resource_type}. Unauthorized access permitted.",
                policy="VULNERABLE_BYPASS",
                required_permission=required_permission,
                user_role=user_role,
                user_id=user_id,
                username=username,
                endpoint=endpoint_path,
                status_code=200,
            )
            log_decision(decision)
            return decision

        # ─────────────────────────────────────────────────────────────────────
        # SECURE MODE: Strict Multi-Layer Authorization
        # ─────────────────────────────────────────────────────────────────────

        # Step 2: BFLA — Function Level Authorization Check
        if resource_type == "ADMIN_FUNCTION" or (endpoint_path and "/admin/" in endpoint_path):
            if user_role != "ADMIN" and not (user_role == "MANAGER" and action in ("READ", "AUDIT")):
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"BFLA Protection: Role '{user_role}' is not authorized to access administrative function '{endpoint_path}'. Administrator privileges required.",
                    policy="BFLA_PROTECTION",
                    required_permission=required_permission or "ADMIN_DASHBOARD",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                )
                log_decision(decision)
                return decision

        # Step 3: RBAC Check (Role Permission Matrix)
        user_perms = ROLE_PERMISSIONS.get(user_role, [])
        if required_permission and required_permission not in user_perms and user_role != "ADMIN":
            decision = AuthorizationDecision(
                decision="DENY",
                reason=f"RBAC Protection: User role '{user_role}' lacks required permission '{required_permission}'.",
                policy="RBAC",
                required_permission=required_permission,
                user_role=user_role,
                user_id=user_id,
                username=username,
                endpoint=endpoint_path,
                status_code=403,
            )
            log_decision(decision)
            return decision

        # Step 4: BOPLA Check (Property Level Authorization for UPDATE operations)
        if action == "UPDATE" and requested_properties:
            injected_privileged = [p for p in requested_properties if p in PRIVILEGED_PROPERTIES]
            if injected_privileged and user_role != "ADMIN":
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"BOPLA Protection: Customer user '{username}' (ID {user_id}) cannot modify privileged properties: {injected_privileged}.",
                    policy="BOPLA_PROTECTION",
                    required_permission="PRIVILEGED_PROPERTY_UPDATE",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                    extra_details={"injected_properties": injected_privileged},
                )
                log_decision(decision)
                return decision

        # Step 5: BOLA Check (Object Level Authorization & Ownership)
        if resource_owner_id is not None:
            resource_owner_id_int = int(resource_owner_id) if str(resource_owner_id).isdigit() else resource_owner_id
            user_id_int = int(user_id) if str(user_id).isdigit() else user_id

            if resource_owner_id_int != user_id_int and user_role not in ("ADMIN", "MANAGER", "SUPPORT"):
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"BOLA Protection: User {username} (ID {user_id}) does not own object {resource_owner_id}. Access denied.",
                    policy="BOLA_PROTECTION",
                    required_permission=f"{resource_type}_READ_OWN",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                )
                log_decision(decision)
                return decision

        # Step 6: ABAC Check (Department & Region contextual matching for Support / Manager)
        if user_role == "SUPPORT":
            res_dept = resource_attributes.get("department") or resource_attributes.get("assigned_department")
            if res_dept and res_dept != user_dept and res_dept != "Customer Support":
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"ABAC Protection: Support Agent department '{user_dept}' does not match ticket/resource department '{res_dept}'.",
                    policy="ABAC",
                    required_permission="TICKET_READ_DEPARTMENT",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                )
                log_decision(decision)
                return decision

        if user_role == "MANAGER":
            res_dept = resource_attributes.get("department")
            res_region = resource_attributes.get("region")
            if res_dept and res_dept != user_dept:
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"ABAC Protection: Manager department '{user_dept}' does not match resource department '{res_dept}'.",
                    policy="ABAC",
                    required_permission="RESOURCE_DEPARTMENT_MATCH",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                )
                log_decision(decision)
                return decision
            if res_region and res_region != user_region and user_region != "Global":
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"ABAC Protection: Manager region '{user_region}' does not match resource region '{res_region}'.",
                    policy="ABAC",
                    required_permission="RESOURCE_REGION_MATCH",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                )
                log_decision(decision)
                return decision

        # Step 7: MAC Check (Sensitivity Level Lattice: Clearance >= Classification)
        if resource_attributes.get("classification"):
            res_class = resource_attributes["classification"]
            res_class_lvl = MAC_LEVELS.get(res_class.upper(), 1)
            if user_clearance_lvl < res_class_lvl:
                decision = AuthorizationDecision(
                    decision="DENY",
                    reason=f"MAC Protection: User clearance level '{user_clearance}' ({user_clearance_lvl}) is lower than document classification level '{res_class}' ({res_class_lvl}). Access denied.",
                    policy="MAC",
                    required_permission=f"CLEARANCE_{res_class}",
                    user_role=user_role,
                    user_id=user_id,
                    username=username,
                    endpoint=endpoint_path,
                    status_code=403,
                    extra_details={"user_clearance": user_clearance, "resource_classification": res_class},
                )
                log_decision(decision)
                return decision

        # If all checks pass in SECURE mode: ALLOW
        decision = AuthorizationDecision(
            decision="ALLOW",
            reason=f"🛡️ SECURE MODE: Authorization policies (RBAC, ABAC, MAC, Ownership) verified successfully for {username}.",
            policy="FULL_AUTHORIZATION_PASSED",
            required_permission=required_permission,
            user_role=user_role,
            user_id=user_id,
            username=username,
            endpoint=endpoint_path,
            status_code=200,
        )
        log_decision(decision)
        return decision
