import httpx
from typing import Dict, List, Any
from app.engine.api_parser import APIEndpoint
from app.engine.object_graph import UserIdentity
from app.engine.manifest import PrivilegeManifest
from app.engine.reporter import Reporter, Finding
from app.core.guardrails import SafetyGuardrails

class BFLAEngine:
    """
    N-Tier BFLA (Function Level Privilege Escalation) Scanner.
    Executes role escalation attacks by calling admin endpoints with regular user tokens.
    """
    def __init__(self, target_base_url: str, guardrails: SafetyGuardrails):
        self.target_base_url = target_base_url.rstrip("/")
        self.guardrails = guardrails

    async def run_bfla_scan(
        self,
        endpoints: List[APIEndpoint],
        regular_user: UserIdentity,
        manifest: PrivilegeManifest
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not self.guardrails.validate_target_url(self.target_base_url):
            return findings

        if self.guardrails.dry_run:
            simulated = Reporter.create_finding(
                finding_id="BFLA-CRAPI-002",
                vuln_key="BFLA_ADMIN",
                title="BFLA: Privilege Escalation to Admin User Management API",
                endpoint_path="/identity/api/v2/admin/users",
                http_method="GET",
                cve_analog="CVE-2023-28432 (BFLA Admin Endpoint Exposure)",
                description="Regular User B successfully listed all system administrative accounts via un-checked endpoint.",
                target_url=self.target_base_url,
                user_token=regular_user.token,
                bypass_payload=[{"user_id": "admin_1", "role": "ADMIN"}, {"user_id": "user_2", "role": "REGULAR"}]
            )
            return [simulated]

        async with httpx.AsyncClient(timeout=10.0) as client:
            for ep in endpoints:
                required_role = manifest.get_endpoint_requirement(ep.path, ep.method)
                is_admin_path = "admin" in ep.path.lower() or "manage" in ep.path.lower()

                if (required_role == "ADMIN" or is_admin_path) and self.guardrails.is_method_allowed(ep.method):
                    url = f"{self.target_base_url}{ep.path}"
                    headers = {"Authorization": f"Bearer {regular_user.token}"}

                    try:
                        res = await client.request(ep.method, url, headers=headers)
                        if res.status_code in [200, 201, 204]:
                            payload = res.json() if "application/json" in res.headers.get("content-type", "") else {}
                            finding = Reporter.create_finding(
                                finding_id=f"BFLA-{ep.method}-{ep.path}",
                                vuln_key="BFLA_ADMIN",
                                title=f"BFLA ({ep.method}): Low-Privilege Access to Administrative Path {ep.path}",
                                endpoint_path=ep.path,
                                http_method=ep.method,
                                cve_analog="CVE-2023-28432",
                                description=f"Regular user ({regular_user.username}) successfully invoked administrative route {ep.path}.",
                                target_url=self.target_base_url,
                                user_token=regular_user.token,
                                bypass_payload=payload
                            )
                            findings.append(finding)
                    except Exception:
                        continue

        return findings
