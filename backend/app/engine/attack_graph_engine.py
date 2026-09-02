"""
Chained Exploit Path & Attack-Graph Analysis Engine (Section 9.6).
Models authorization vulnerabilities as nodes in a directed attack graph where edges represent
capability grants (e.g. BOLA discover ID -> BOPLA inject role -> BFLA export database).
"""
from typing import Dict, List, Any
from app.engine.authz_engine import get_security_mode

def generate_attack_graph() -> Dict[str, Any]:
    mode = get_security_mode()
    is_vuln = mode == "vulnerable"

    nodes = [
        {
            "id": "entry",
            "label": "Legitimate Low-Privilege Login",
            "type": "IDENTITY",
            "status": "COMPROMISED" if is_vuln else "AUTHENTICATED",
            "details": "Alice Johnson (ID 101, Role: CUSTOMER)",
        },
        {
            "id": "bola_node",
            "label": "BOLA (API1:2023) Object ID Enumeration",
            "type": "VULNERABILITY",
            "status": "EXPLOITABLE" if is_vuln else "BLOCKED",
            "details": "Sequential IDs 101..115 exposed via GET /api/v1/bank/users/{id}",
        },
        {
            "id": "bopla_node",
            "label": "BOPLA (API3:2023) Role Mass Assignment",
            "type": "VULNERABILITY",
            "status": "EXPLOITABLE" if is_vuln else "BLOCKED",
            "details": "PATCH /api/v1/bank/users/101 accepts injected {'role': 'ADMIN'}",
        },
        {
            "id": "bfla_node",
            "label": "BFLA (API5:2023) Admin Function Boundary Bypass",
            "type": "VULNERABILITY",
            "status": "EXPLOITABLE" if is_vuln else "BLOCKED",
            "details": "GET /api/v1/bank/admin/users accessible without ADMIN role check",
        },
        {
            "id": "impact_node",
            "label": "Full Customer Database Exposure",
            "type": "IMPACT",
            "status": "ACHIEVED" if is_vuln else "PREVENTED",
            "details": "All customer PII & financial records exfiltrated",
        },
    ]

    edges = [
        {
            "source": "entry",
            "target": "bola_node",
            "relationship": "Tamper Object ID",
            "active": is_vuln,
        },
        {
            "source": "bola_node",
            "target": "bopla_node",
            "relationship": "Infers Privileged Fields",
            "active": is_vuln,
        },
        {
            "source": "bopla_node",
            "target": "bfla_node",
            "relationship": "Grants Admin Role Capability",
            "active": is_vuln,
        },
        {
            "source": "bfla_node",
            "target": "impact_node",
            "relationship": "Exfiltrates Entire DB",
            "active": is_vuln,
        },
    ]

    return {
        "title": "Chained Exploit Path & Attack-Graph Model",
        "security_mode": mode,
        "attack_chain_status": "VULNERABLE CHAIN EXPLOITABLE" if is_vuln else "PIPELINE DEFENSE ACTIVE — ALL EDGES SEVERED",
        "graph": {
            "nodes": nodes,
            "edges": edges,
        },
        "chain_narrative": "One legitimate login -> one guessed field -> one guessed admin path -> entire customer database."
    }
