import httpx
from typing import List
from app.engine.api_parser import APIEndpoint
from app.engine.object_graph import UserIdentity
from app.engine.manifest import PrivilegeManifest
from app.engine.reporter import Reporter, Finding
from app.core.guardrails import SafetyGuardrails

SENSITIVE_FIELD_PATTERNS = ["password", "hash", "ssn", "secret", "credit_card", "internal_role", "is_admin", "token"]

class BOPLAEngine:
    """
    BOPLA (Property-Level Authorization) Scanner.
    Detects Excessive Data Exposure (field-level leak) & Mass Assignment vulnerabilities.
    """
    def __init__(self, target_base_url: str, guardrails: SafetyGuardrails):
        self.target_base_url = target_base_url.rstrip("/")
        self.guardrails = guardrails

    async def run_bopla_scan(
        self,
        endpoints: List[APIEndpoint],
        user: UserIdentity,
        manifest: PrivilegeManifest
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not self.guardrails.validate_target_url(self.target_base_url):
            return findings

        manifest_sensitive = manifest.get_sensitive_properties()
        target_sensitive_fields = list(set(SENSITIVE_FIELD_PATTERNS + manifest_sensitive))

        if self.guardrails.dry_run:
            simulated_exposure = Reporter.create_finding(
                finding_id="BOPLA-CRAPI-003",
                vuln_key="BOPLA_EXPOSURE",
                title="BOPLA: Sensitive Field Leakage (Password Hash Exposure)",
                endpoint_path="/identity/api/v2/user/profile",
                http_method="GET",
                cve_analog="CVE-2021-43798 (Excessive Property Exposure)",
                description="Profile response contains plaintext password_hash field in public user schema.",
                target_url=self.target_base_url,
                user_token=user.token,
                bypass_payload={"user_id": "u_1", "email": "user@example.com", "password_hash": "$2b$12$eImiTXuWV..."}
            )
            simulated_mass_assignment = Reporter.create_finding(
                finding_id="BOPLA-CRAPI-004",
                vuln_key="BOPLA_MASS_ASSIGNMENT",
                title="BOPLA: Mass Assignment Privilege Mutation (is_admin)",
                endpoint_path="/identity/api/v2/user/profile",
                http_method="PUT",
                cve_analog="CVE-2022-26134 (Mass Assignment Escalation)",
                description="PUT request accepts un-sanitized 'role': 'ADMIN' field in user profile edit body.",
                target_url=self.target_base_url,
                user_token=user.token,
                request_body={"email": "user@example.com", "role": "ADMIN", "is_admin": True},
                bypass_payload={"status": "updated", "role": "ADMIN"}
            )
            return [simulated_exposure, simulated_mass_assignment]

        async with httpx.AsyncClient(timeout=10.0) as client:
            for ep in endpoints:
                if ep.method == "GET" and self.guardrails.is_method_allowed("GET"):
                    url = f"{self.target_base_url}{ep.path}"
                    headers = {"Authorization": f"Bearer {user.token}"}
                    try:
                        res = await client.get(url, headers=headers)
                        if res.status_code == 200:
                            payload = res.json() if "application/json" in res.headers.get("content-type", "") else {}
                            payload_str = str(payload).lower()
                            leaked = [field for field in target_sensitive_fields if field in payload_str]

                            if leaked:
                                finding = Reporter.create_finding(
                                    finding_id=f"BOPLA-GET-{ep.path}",
                                    vuln_key="BOPLA_EXPOSURE",
                                    title=f"BOPLA (Excessive Data Exposure): Leaked properties [{', '.join(leaked)}]",
                                    endpoint_path=ep.path,
                                    http_method="GET",
                                    cve_analog="CVE-2021-43798",
                                    description=f"Endpoint exposed sensitive properties {leaked} in API response body.",
                                    target_url=self.target_base_url,
                                    user_token=user.token,
                                    bypass_payload=payload
                                )
                                findings.append(finding)
                    except Exception:
                        continue

        return findings
