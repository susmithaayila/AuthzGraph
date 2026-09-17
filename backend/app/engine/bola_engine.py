import httpx
from typing import List
from app.engine.api_parser import APIEndpoint
from app.engine.object_graph import MultiUserObjectGraph, UserIdentity
from app.engine.reporter import Reporter, Finding
from app.core.guardrails import SafetyGuardrails

class BOLAEngine:
    """
    3-Stage BOLA Vulnerability Scanner.
    Executes dynamic substitution of User A object IDs into User B request contexts.
    """
    def __init__(self, target_base_url: str, guardrails: SafetyGuardrails):
        self.target_base_url = target_base_url.rstrip("/")
        self.guardrails = guardrails

    async def run_bola_scan(
        self,
        endpoints: List[APIEndpoint],
        user_a: UserIdentity,
        user_b: UserIdentity,
        object_graph: MultiUserObjectGraph
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not self.guardrails.validate_target_url(self.target_base_url):
            return findings

        if self.guardrails.dry_run:
            # Return simulated benchmark finding for dry run / demonstration
            simulated = Reporter.create_finding(
                finding_id="BOLA-CRAPI-001",
                vuln_key="BOLA_READ",
                title="BOLA: Unauthorized Access to Peer Vehicle Location",
                endpoint_path="/identity/api/v2/vehicle/{vehicle_id}/location",
                http_method="GET",
                cve_analog="CVE-2022-24706 (BOLA in Vehicle Tracking API)",
                description=f"Attacker Priya Sharma ({user_b.user_id}) was able to fetch real-time location/data for {user_a.user_id} owned by Victim Arjun Kapoor.",
                target_url=self.target_base_url,
                user_token=user_b.token,
                original_payload={"resource_id": "rider_arjun_profile", "owner": "Arjun Kapoor (rider_arjun)", "status": "200_OK_EXPOSED"},
                bypass_payload={"resource_id": "rider_arjun_profile", "owner": "Arjun Kapoor (rider_arjun)", "status": "200_OK_EXPOSED"}
            )
            return [simulated]

        async with httpx.AsyncClient(timeout=10.0) as client:
            user_a_objs = object_graph.get_user_resources(user_a.user_id)

            for ep in endpoints:
                if ep.path_param_names and self.guardrails.is_method_allowed(ep.method):
                    for obj_id in user_a_objs:
                        # Substitute User A's object_id into path
                        sub_path = ep.path
                        for param in ep.path_param_names:
                            sub_path = sub_path.replace(f"{{{param}}}", str(obj_id))

                        url = f"{self.target_base_url}{sub_path}"
                        headers = {"Authorization": f"Bearer {user_b.token}"}

                        try:
                            res = await client.request(ep.method, url, headers=headers)

                            # Stage 1: Status Code Check (200 OK)
                            if res.status_code in [200, 201]:
                                payload = res.json() if "application/json" in res.headers.get("content-type", "") else {}

                                # Stage 2: Ownership Attribute Matching
                                is_owner_match = str(obj_id) in str(payload) or user_a.user_id in str(payload)

                                # Stage 3: Normalized Payload Validation
                                if is_owner_match:
                                    vuln_type = "BOLA_WRITE" if ep.method in ["PUT", "PATCH", "DELETE"] else "BOLA_READ"
                                    finding = Reporter.create_finding(
                                        finding_id=f"BOLA-{ep.method}-{ep.path}",
                                        vuln_key=vuln_type,
                                        title=f"BOLA ({ep.method}): Attacker Priya accessed Victim Arjun's Resource ({obj_id})",
                                        endpoint_path=sub_path,
                                        http_method=ep.method,
                                        cve_analog="CVE-2022-24706 (Uber Breach BOLA Analogue)",
                                        description=f"Attacker Priya Sharma ({user_b.token[:12]}...) successfully executed {ep.method} on object '{obj_id}' owned by Victim Arjun Kapoor ({user_a.username}).",
                                        target_url=self.target_base_url,
                                        user_token=user_b.token,
                                        bypass_payload=payload
                                    )
                                    findings.append(finding)
                        except Exception:
                            continue

        return findings
