from typing import Dict, List, Any
from pydantic import BaseModel, Field

class Finding(BaseModel):
    id: str
    title: str
    vulnerability_class: str  # BOLA, BFLA, BOPLA
    severity: str             # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    cvss_vector: str
    endpoint_path: str
    http_method: str
    owasp_category: str
    cve_analog: str
    description: str
    curl_reproduction: str
    remediation_snippets: Dict[str, str] = Field(default_factory=dict)
    original_payload: Any = None
    bypass_payload: Any = None

CVSS_MATRIX = {
    "BOLA_READ": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "score": 6.5,
        "severity": "MEDIUM",
        "owasp": "API1:2023 - Broken Object Level Authorization"
    },
    "BOLA_WRITE": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
        "score": 8.1,
        "severity": "HIGH",
        "owasp": "API1:2023 - Broken Object Level Authorization"
    },
    "BFLA_ADMIN": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "score": 8.8,
        "severity": "HIGH",
        "owasp": "API5:2023 - Broken Function Level Authorization"
    },
    "BOPLA_EXPOSURE": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        "score": 4.3,
        "severity": "MEDIUM",
        "owasp": "API3:2023 - Broken Object Property Level Authorization"
    },
    "BOPLA_MASS_ASSIGNMENT": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "score": 6.5,
        "severity": "MEDIUM",
        "owasp": "API3:2023 - Broken Object Property Level Authorization"
    }
}

REMEDIATION_TEMPLATES = {
    "Python (FastAPI)": '''# FastAPI Authorization Dependency Check
@app.get("/api/v1/resources/{resource_id}")
async def get_resource(resource_id: str, current_user: User = Depends(get_current_user)):
    resource = await db.get_resource(resource_id)
    if not resource or resource.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden: You do not own this object")
    return resource''',

    "Node.js (Express)": '''// Express.js Ownership Guard Middleware
async function checkObjectOwnership(req, res, next) {
    const resource = await db.findResource(req.params.id);
    if (!resource || resource.ownerId !== req.user.id) {
        return res.status(403).json({ error: "Access Denied: Object ownership mismatch" });
    }
    next();
}''',

    "Java (Spring Boot)": '''// Spring Security PreAuthorize Ownership Check
@GetMapping("/api/v1/resources/{id}")
@PreAuthorize("@securityService.isResourceOwner(#id, authentication.principal.id)")
public ResponseEntity<Resource> getResource(@PathVariable String id) {
    return ResponseEntity.ok(resourceService.getById(id));
}'''
}

class Reporter:
    """Generates deterministic CVSS-scored vulnerability reports and cURL reproduction scripts."""

    @staticmethod
    def create_finding(
        finding_id: str,
        vuln_key: str,
        title: str,
        endpoint_path: str,
        http_method: str,
        cve_analog: str,
        description: str,
        target_url: str,
        user_token: str,
        request_body: Any = None,
        original_payload: Any = None,
        bypass_payload: Any = None
    ) -> Finding:
        meta = CVSS_MATRIX.get(vuln_key, CVSS_MATRIX["BOLA_READ"])

        # Build cURL reproduction command
        curl_cmd = f"curl -X {http_method.upper()} \"{target_url.rstrip('/')}{endpoint_path}\" \\\n"
        curl_cmd += f"  -H \"Authorization: Bearer {user_token}\" \\\n"
        curl_cmd += "  -H \"Content-Type: application/json\""
        if request_body:
            import json
            curl_cmd += f" \\\n  -d '{json.dumps(request_body)}'"

        return Finding(
            id=finding_id,
            title=title,
            vulnerability_class=vuln_key.split("_")[0],
            severity=meta["severity"],
            cvss_score=meta["score"],
            cvss_vector=meta["vector"],
            endpoint_path=endpoint_path,
            http_method=http_method.upper(),
            owasp_category=meta["owasp"],
            cve_analog=cve_analog,
            description=description,
            curl_reproduction=curl_cmd,
            remediation_snippets=REMEDIATION_TEMPLATES,
            original_payload=original_payload,
            bypass_payload=bypass_payload
        )
