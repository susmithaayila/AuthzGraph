"""
Runner for Task 4: Per-stage decision traces from live execution.
Executes the 10 attack vectors against fully-mediated SecureBank,
then runs single-layer ablation tests against the corresponding vectors.
Logs are taken directly from the server's SECURITY_DECISION_LOGS / HTTP response.
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient

from main import app
from app.engine.authz_engine import (
    ALL_VALID_LAYERS,
    set_security_mode,
    set_active_layers,
    get_decision_logs,
    clear_decision_logs,
)

client = TestClient(app)

ALICE_TOKEN = "token_alice"                  # User 101, CUSTOMER, South, CONFIDENTIAL
MANAGER_NORTH_TOKEN = "token_manager_north"  # User 302, MANAGER, North, CONFIDENTIAL
ADMIN_TOKEN = "token_admin"                  # User 401, ADMIN, Global, SECRET

headers_alice = {"Authorization": f"Bearer {ALICE_TOKEN}"}
headers_mgr_north = {"Authorization": f"Bearer {MANAGER_NORTH_TOKEN}"}
headers_admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# ─────────────────────────────────────────────────────────────────────────────
# Part 1: 10 Attack Vectors against Fully Mediated Engine
# ─────────────────────────────────────────────────────────────────────────────
print("=========================================================================================")
print("PART 1: 10 ATTACK VECTORS AGAINST FULLY MEDIATED SECUREBANK (ALL CONTROLS ACTIVE)")
print("=========================================================================================")

set_security_mode("secure")
set_active_layers(list(ALL_VALID_LAYERS))
clear_decision_logs()

VECTORS = [
    {
        "vector": "BOLA_SINGLE_OBJECT",
        "method": "GET",
        "url": "/api/v1/bank/users/102",
        "headers": headers_alice,
        "json": None,
    },
    {
        "vector": "BOLA_ENUMERATION",
        "method": "GET",
        "url": "/api/v1/bank/accounts/ACC-102",
        "headers": headers_alice,
        "json": None,
    },
    {
        "vector": "BOPLA_MASS_ASSIGNMENT",
        "method": "PATCH",
        "url": "/api/v1/bank/users/101",
        "headers": headers_alice,
        "json": {"role": "ADMIN", "accountBalance": 999999.0},
    },
    {
        "vector": "BFLA_ADMIN_PROBING",
        "method": "GET",
        "url": "/api/v1/bank/admin/users",
        "headers": headers_alice,
        "json": None,
    },
    {
        "vector": "BFLA_VERB_SWITCHING",
        "method": "DELETE",
        "url": "/api/v1/bank/admin/users/102",
        "headers": headers_alice,
        "json": None,
    },
    {
        "vector": "ABAC_CROSS_REGION",
        "method": "GET",
        "url": "/api/v1/bank/documents/506",
        "headers": headers_mgr_north,
        "json": None,
    },
    {
        "vector": "ABAC_CROSS_DEPARTMENT",
        "method": "GET",
        "url": "/api/v1/bank/documents/511",
        "headers": headers_mgr_north,
        "json": None,
    },
    {
        "vector": "MAC_READ_UP_VIOLATION",
        "method": "GET",
        "url": "/api/v1/bank/documents/508",
        "headers": headers_alice,
        "json": None,
    },
    {
        "vector": "MAC_WRITE_DOWN_VIOLATION",
        "method": "PATCH",
        "url": "/api/v1/bank/documents/507/classify",
        "headers": headers_admin,
        "json": {"classification": "PUBLIC"},
    },
    {
        "vector": "RBAC_PERMISSION_DENIED",
        "method": "GET",
        "url": "/api/v1/bank/audit-summary",
        "headers": headers_alice,
        "json": None,
    },
]

part1_results = []

for item in VECTORS:
    clear_decision_logs()
    res = client.request(
        item["method"],
        item["url"],
        headers=item["headers"],
        json=item["json"]
    )
    logs = get_decision_logs(1)
    if logs:
        log = logs[0]
        part1_results.append({
            "vector": item["vector"],
            "endpoint": f"{item['method']} {item['url']}",
            "http_status": res.status_code,
            "decision": log["decision"],
            "denying_stage": log["policy"],
            "reason": log["reason"]
        })
    else:
        part1_results.append({
            "vector": item["vector"],
            "endpoint": f"{item['method']} {item['url']}",
            "http_status": res.status_code,
            "decision": "UNKNOWN",
            "denying_stage": "NONE",
            "reason": str(res.json())
        })

print(f"{'Vector':<26} | {'Endpoint':<38} | {'Status':<6} | {'Stage':<18} | {'Reason'}")
print("-" * 130)
for r in part1_results:
    print(f"{r['vector']:<26} | {r['endpoint']:<38} | {r['http_status']:<6} | {r['denying_stage']:<18} | {r['reason']}")

print()
# ─────────────────────────────────────────────────────────────────────────────
# Part 2: Single-Control Ablations (Ablating 1 Control at a Time)
# ─────────────────────────────────────────────────────────────────────────────
print("=========================================================================================")
print("PART 2: SINGLE-CONTROL ABLATIONS (TARGET VECTOR RUN WITH TARGET CONTROL DISABLED)")
print("=========================================================================================")

ABLATION_RUNS = [
    {
        "disabled_control": "RBAC",
        "vector_name": "RBAC_PERMISSION_DENIED",
        "method": "GET",
        "url": "/api/v1/bank/audit-summary",
        "headers": headers_alice,
        "json": None,
    },
    {
        "disabled_control": "BFLA",
        "vector_name": "BFLA_ADMIN_PROBING",
        "method": "GET",
        "url": "/api/v1/bank/admin/users",
        "headers": headers_alice,
        "json": None,
    },
    {
        "disabled_control": "BOPLA",
        "vector_name": "BOPLA_MASS_ASSIGNMENT",
        "method": "PATCH",
        "url": "/api/v1/bank/users/101",
        "headers": headers_alice,
        "json": {"role": "ADMIN", "accountBalance": 999999.0},
    },
    {
        "disabled_control": "BOLA",
        "vector_name": "BOLA_SINGLE_OBJECT",
        "method": "GET",
        "url": "/api/v1/bank/users/102",
        "headers": headers_alice,
        "json": None,
    },
    {
        "disabled_control": "ABAC",
        "vector_name": "ABAC_CROSS_REGION",
        "method": "GET",
        "url": "/api/v1/bank/documents/506",
        "headers": headers_mgr_north,
        "json": None,
    },
    {
        "disabled_control": "MAC",
        "vector_name": "MAC_READ_UP_VIOLATION",
        "method": "GET",
        "url": "/api/v1/bank/documents/508",
        "headers": headers_alice,
        "json": None,
    },
    {
        "disabled_control": "MAC (Write-Down)",
        "vector_name": "MAC_WRITE_DOWN_VIOLATION",
        "method": "PATCH",
        "url": "/api/v1/bank/documents/507/classify",
        "headers": headers_admin,
        "json": {"classification": "PUBLIC"},
    },
]

part2_results = []

for test in ABLATION_RUNS:
    ctrl = test["disabled_control"].split()[0]
    active = [l for l in ALL_VALID_LAYERS if l != ctrl]
    set_active_layers(active)
    clear_decision_logs()

    res = client.request(
        test["method"],
        test["url"],
        headers=test["headers"],
        json=test["json"]
    )
    logs = get_decision_logs(1)
    if logs:
        log = logs[0]
        part2_results.append({
            "disabled_control": test["disabled_control"],
            "vector": test["vector_name"],
            "endpoint": f"{test['method']} {test['url']}",
            "http_status": res.status_code,
            "final_decision": log["decision"],
            "logged_stage": log["policy"],
            "reason": log["reason"]
        })
    else:
        part2_results.append({
            "disabled_control": test["disabled_control"],
            "vector": test["vector_name"],
            "endpoint": f"{test['method']} {test['url']}",
            "http_status": res.status_code,
            "final_decision": "ALLOW" if res.status_code == 200 else "DENY",
            "logged_stage": "NONE",
            "reason": "Request allowed (HTTP 200 OK)" if res.status_code == 200 else str(res.json())
        })

print(f"{'Disabled Control':<20} | {'Target Vector':<26} | {'Status':<6} | {'Decision':<8} | {'Stage Logged':<16} | {'Logged Reason'}")
print("-" * 135)
for r in part2_results:
    print(f"{r['disabled_control']:<20} | {r['vector']:<26} | {r['http_status']:<6} | {r['final_decision']:<8} | {r['logged_stage']:<16} | {r['reason']}")

# Reset to all layers
set_active_layers(list(ALL_VALID_LAYERS))
