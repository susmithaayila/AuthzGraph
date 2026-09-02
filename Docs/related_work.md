# Related Work & Comparative Literature Review

## 1. Comparative Analysis Matrix

The table below positions **AuthzGraph** against the two most directly comparable prior works (Barabanov et al. 2022 and AuthProbe 2026) as well as existing commercial API security scanners, open-source penetration tools, and state-of-the-art academic stateful fuzzers.

| Tool | Object-level (BOLA) | Property-level (BOPLA) | Function-level (BFLA) | Multi-identity | Layer-ablation study | Cross-app validation |
|---|---|---|---|---|---|---|
| Barabanov et al. 2022 | Yes | No | No | No | No | Not reported |
| AuthProbe 2026 | Yes | No | No | Yes | No | Not reported |
| RESTler (Atlidakis et al., ICSE 2019) | Partial (stateful fuzzing) | No | No | No | No | No |
| 42Crunch API Security Platform | Yes | Partial (schema linting) | Yes | No | No | No |
| Astra (Open-Source API Pentest Tool) | Yes | Partial | Yes | No | No | No |
| IDORFinder / Academic IDOR Scanners | Yes | No | No | No | No | No |
| **AuthzGraph (this work)** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |

---

## 2. Synthesis of Prior Academic Literature

### A. Directly Comparable Prior Works

#### Barabanov et al. (2022) — "Automatic detection of access control vulnerabilities via API specification processing" [arXiv:2201.10833]

Barabanov et al. present a systematic study that reviews IDOR (Insecure Direct Object Reference) / BOLA attack patterns from a wide literature survey and bug-bounty writeup corpus, then proposes an algorithm for detecting such vulnerabilities by processing OpenAPI specifications. The key contribution is a formalized definition of BOLA attack surface derived from path parameters and identity-bound resource schemas. However, the scope is intentionally limited to the object level (BOLA): the authors do not address property-level unauthorized modification (BOPLA / mass assignment) or function-level boundary violations (BFLA), and their evaluation is conducted with a single attacker identity rather than multiple simultaneous identities. No ablation study is reported isolating which specific enforcement mechanism is responsible for blocking which attack class.

#### AuthProbe (2026) — "Specification-Driven, Multi-Identity Detection of Broken Object-Level Authorization" [arXiv:2607.20574]

AuthProbe is an open-source, black-box, OpenAPI-driven scanner that extends the single-identity paradigm of Barabanov et al. by logging in as two or more distinct identities, then diffing cross-identity object access responses to detect BOLA/IDOR violations. This multi-identity approach more closely mirrors real attacker behavior and positions the tool explicitly for CI/CD integration gating — it includes an authorized-use-only safeguard to prevent misuse against unauthorized targets. AuthProbe represents the current state of the art for specification-driven BOLA detection at the time of this writing. However, its scope remains the object level exclusively: BOPLA and BFLA attack vectors are not addressed, and no ablation study isolating individual enforcement layers is reported or claimed.

### B. Differentiating AuthzGraph from Prior Work

Both Barabanov et al. (2022) and AuthProbe (2026) are specification-driven and, in AuthProbe's case, multi-identity, matching AuthzGraph's detection methodology for the object-level layer. Neither system extends detection to the property level (BOPLA) or function level (BFLA), and neither reports a layer-ablation study establishing which specific enforcement mechanism is responsible for closing which specific vulnerability class.

AuthzGraph's contribution is threefold relative to this prior work: (1) a unified, specification-driven, multi-identity detection methodology covering all three authorization layers (object, property, function) rather than object level alone; (2) a formal layer-ablation methodology empirically isolating the necessity of each of RBAC, ABAC, MAC (both Bell-LaPadula properties: No-Read-Up and No-Write-Down / star property), BOPLA-whitelisting, and BOLA-ownership checking — a contribution not present in either prior system; and (3) cross-application generalizability validation (demonstrated against vAPI, an independently-built target) proving the same detection engine transfers to a target it was not designed around, without modification.

---

### C. Stateful API Fuzzing & Dynamic Analysis

* **RESTler (ICSE 2019)**: Atlidakis et al. introduced the first stateful REST API fuzzer that analyzes OpenAPI specifications to infer producer-consumer dependencies between endpoints. While highly effective for discovering 5xx server errors and state sequence bugs, RESTler lacks user identity context and cannot evaluate multi-user authorization flaws (BOLA/BFLA).
* **PyFuzz / APIFuzz**: Focus primarily on input validation, SQL injection, and crash detection rather than semantic authorization logic across distinct security roles.

### D. Authorization Misuse & IDOR Detection

* **AuthScope / AuthAnalyzer**: Burp Suite extensions that automate header swapping between two user sessions. While useful for manual penetration testing, they rely on passive proxy diffing and lack an internal model of resource ownership graphs or property-level field allowlisting (BOPLA).
* **OWASP API Security Top 10 (2023 Edition)**: Highlights that BOLA (API1), BOPLA (API3), and BFLA (API5) represent the majority of real-world API breaches (e.g., USPS 2018, Panera Bread 2018, T-Mobile 2018).

---

## 3. Key Differentiators of AuthzGraph

1. **Unified Hybrid Pipeline**: Unifies RBAC, ABAC, MAC (both Bell-LaPadula No-Read-Up and No-Write-Down / star property), BOLA (ownership graph), BOPLA (property allowlisting), and BFLA (endpoint boundary checks) into a single deterministic evaluation chain.

2. **Empirical Layer Attribution**: Provides a formal ablation methodology proving that no single access control model (e.g. RBAC-only or ABAC-only) can eliminate all OWASP authorization vulnerability classes. Each layer's necessity is confirmed by an isolated exposure-rate measurement in the ablation matrix.

3. **MAC Star Property Implementation**: Unlike most research and open-source implementations that enforce only Bell-LaPadula No-Read-Up, AuthzGraph additionally enforces No-Write-Down (star property): a user with SECRET clearance may not downgrade a document to PUBLIC, even if they are its owner. This bidirectional MAC enforcement provides materially stronger theoretical guarantees.

4. **Cross-Application Generalizability**: Validated against vAPI (github.com/roottusk/vapi), an independently-developed vulnerable target, without any modification to the engine.

5. **Reproducibility**: A dedicated experiments/report_generator.py script reads benchmark and ablation result JSON files and emits ready-to-paste Markdown and LaTeX tables, ensuring all paper numbers are traceable to real HTTP evidence.

---

## 4. Historical Incident Accuracy Note

This project references the following real incidents. A strict distinction is maintained between Authorization failures (which AuthzGraph addresses) and Authentication failures (which it does not):

- **Uber, 2016** (~57M records, AWS credentials found on GitHub): a credential/secrets-management failure. Not a BOLA/BOPLA/BFLA case.
- **Uber, 2022** (internal tools breached via MFA fatigue / phishing): a broken authentication / excessive-standing-privilege incident. No API object authorization failure was involved. Do not attach the 57M figure to this event.
- **USPS, 2018** (~60M records via unauthenticated API + sequential ID enumeration): a genuine BOLA pattern.
- **Panera Bread, 2018** (millions of records via guessable sequential IDs): a genuine BOLA pattern.
- **T-Mobile, 2018-2023** (mass data scraping via unprotected endpoints): BOLA + insufficient rate limiting.

RideX's vulnerabilities are modeled on the USPS, Panera, and T-Mobile patterns — not on the Uber incidents, which are retained only as contrast material distinguishing AuthN failures from AuthZ failures.
