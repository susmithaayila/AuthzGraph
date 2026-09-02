# AuthzGraph Threat Model & Security Posture Specification

## 1. Overview & Operational Assumptions

This document formally defines the **threat model**, **attacker capabilities**, **target security boundaries**, and **out-of-scope risks** for the AuthzGraph microservice authorization engine.

The system assumes a modern REST microservice deployment architecture where authentication (token verification, session issuance) is handled at ingress or by an Identity Provider (IdP). AuthzGraph enforces **Complete Mediation** on every incoming API request at the application/gateway layer before request logic executes.

---

## 2. Attacker Capabilities

The adversary $\mathcal{A}$ is modeled as an authenticated, malicious or compromised actor operating within the multi-user ecosystem with the following explicit capabilities:

1. **Valid Credentials & Identity**: The attacker possesses a valid, unprivileged account (e.g. `CUSTOMER` role) and a valid session token (JWT/Bearer).
2. **Client-Side Traffic Manipulation**: The attacker can inspect, intercept, modify, and replay any outgoing or incoming HTTP traffic using browser DevTools or proxy tools (e.g., Burp Suite, OWASP ZAP, Postman).
3. **Identifier Parameter Substitution**: The attacker can modify path parameters (e.g. `/users/{id}`, `/accounts/{id}`), query parameters, and request body JSON keys.
4. **Property Injection / Mass Assignment**: The attacker can append arbitrary JSON attributes to HTTP `POST`, `PUT`, or `PATCH` request bodies (e.g., injecting `"role": "ADMIN"` or `"accountBalance": 999999`).
5. **Endpoint Boundary Probing**: The attacker can attempt direct HTTP requests to administrative or restricted endpoints (e.g., `/admin/users`, `/admin/audit-logs`) and experiment with HTTP verb switching (`GET` vs. `DELETE`).

---

## 3. Attacker Goals (Target Vulnerability Classes)

The adversary aims to breach one or more of the following security guarantees:

* **Horizontal Privilege Escalation (BOLA / OWASP API1)**: Accessing or modifying data objects belonging to another legitimate user without authorization.
* **Property-Level Compromise (BOPLA / OWASP API3)**:
  * *Excessive Data Exposure*: Reading forbidden or internal attributes exposed in API JSON responses.
  * *Mass Assignment*: Overwriting privileged model properties via unchecked client input binding.
* **Vertical Privilege Escalation (BFLA / OWASP API5)**: Invoking administrative operations or restricted endpoints without holding the required system role.
* **Contextual & Sensitivity Violations (ABAC / MAC)**: Bypassing departmental/regional boundaries or accessing documents above their clearance level.

---

## 4. Out-of-Scope Threat Vectors

The following attack surfaces are explicitly out of scope for AuthzGraph's enforcement engine and are assumed to be mitigated by infrastructure controls:

1. **Unauthenticated Transport Attacks**: Interception of plaintext HTTP traffic (mitigated by TLS/HTTPS).
2. **Identity Provider & Token Compromise**: Stolen private keys, weak JWT signature algorithms, or credential phishing.
3. **Infrastructure & Supply Chain Attacks**: Vulnerabilities in underlying operating systems, container runtimes, or third-party PyPI/NPM packages.
4. **Distributed Denial of Service (DDoS)**: Network volumetric exhaustion (mitigated by Cloudflare / AWS WAF rate-limiting).
