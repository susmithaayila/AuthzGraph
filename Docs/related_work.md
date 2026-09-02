# Related Work & Comparative Literature Review

## 1. Comparative Analysis Matrix

The table below positions **AuthzGraph** against existing commercial API security scanners, open-source penetration tools, and state-of-the-art academic stateful fuzzers.

| Tool / Paper | BOLA Detection | BOPLA Detection | BFLA Detection | Dynamic OpenAPI Ingestion | Hybrid RBAC–ABAC–MAC Pipeline | Layer-Ablation Empirical Proof |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **RESTler** (Atlidakis et al., ICSE 2019) | Partial (via stateful fuzzing) | ❌ No | ❌ No | ✅ Yes | ❌ No | ❌ No |
| **42Crunch API Security Platform** | ✅ Yes | Partial (Schema linting) | ✅ Yes | ✅ Yes | ❌ No (Rule-based static linting) | ❌ No |
| **Astra** (Open-Source API Pentest Tool) | ✅ Yes | Partial | ✅ Yes | ✅ Yes | ❌ No | ❌ No |
| **Pynt / Salt Security** | ✅ Yes | Partial | ✅ Yes | ✅ Yes | ❌ No (ML anomaly detection) | ❌ No |
| **IDORFinder / Academic IDOR Scanners** | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No | ❌ No |
| **AuthzGraph (This Work)** | **✅ Yes** | **✅ Yes** | **✅ Yes** | **✅ Yes** | **✅ Yes (Unified 6-Layer Pipeline)** | **✅ Yes (Empirically Validated)** |

---

## 2. Synthesis of Prior Academic Literature

### A. Stateful API Fuzzing & Dynamic Analysis
* **RESTler (ICSE 2019)**: Atlidakis et al. introduced the first stateful REST API fuzzer that analyzes OpenAPI specifications to infer producer-consumer dependencies between endpoints. While highly effective for discovering 5xx server errors and state sequence bugs, RESTler lacks user identity context and cannot evaluate multi-user authorization flaws (BOLA/BFLA).
* **PyFuzz / APIFuzz**: Focus primarily on input validation, SQL injection, and crash detection rather than semantic authorization logic across distinct security roles.

### B. Authorization Misuse & IDOR Detection
* **AuthScope / AuthAnalyzer**: Burp Suite extensions that automate header swapping between two user sessions. While useful for manual penetration testing, they rely on passive proxy diffing and lack an internal model of resource ownership graphs or property-level field allowlisting (BOPLA).
* **OWASP API Security Top 10 (2023 Edition)**: Highlights that BOLA (API1), BOPLA (API3), and BFLA (API5) represent the majority of real-world API breaches (e.g., USPS 2018, Panera Bread 2018, T-Mobile 2018).

---

## 3. Key Differentiators of AuthzGraph

1. **Unified Hybrid Pipeline**: Unifies RBAC (role-function matrix), ABAC (contextual department/region matching), MAC (sensitivity clearance lattice), BOLA (ownership graph), BOPLA (property allowlisting), and BFLA (endpoint boundary checks) into a single deterministic evaluation chain.
2. **Empirical Layer Attribution**: Provides a formal ablation methodology proving that no single access control model (e.g. RBAC-only or ABAC-only) can eliminate all three OWASP authorization vulnerability classes.
