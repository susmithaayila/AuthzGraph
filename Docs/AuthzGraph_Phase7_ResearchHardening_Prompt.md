# PROMPT FOR ANTIGRAVITY — AuthzGraph Phase 7: Research-Grade Hardening

Paste everything below into Antigravity as one instruction. Work through Parts A–E in order; Part F is optional if time allows. At the end, run the "Definition of Done" checklist and report the actual output of each command — do not just say it passed.

---

## CONTEXT

Repo: `susmithaayila/AuthzGraph`. Backend = FastAPI (`backend/app/engine/*`, `backend/app/api/routes.py`), research harness = `backend/experiments/{benchmark.py, ablation.py, generate_charts.py, run_all.py}`, target app = `target_app/main.py` ("RideX"), paper draft = `Docs/AuthzGraph_Conference_Paper_Draft.md`, related work = `Docs/related_work.md`. Tests currently pass (21/21). The benchmark and ablation harnesses are real — they make live HTTP calls against the running FastAPI server and compute real statistics, not mocked numbers. Do not break this property in any of the work below: every new metric must come from an actual HTTP round-trip against a running server, never a hardcoded/simulated value.

Do NOT attempt to attack, scan, or point any part of this system at a real production/third-party service. Every target in this phase is either code you already own (`target_app/`) or an open-source project you will run **locally on localhost**.

---

## PART A — Fix the Uber 2022 Historical Accuracy Error

**File:** `target_app/main.py` (header docstring) and any other file referencing the Uber 2022 incident (grep the repo for "Uber", "57 million", "MFA fatigue" — check `Docs/*.md` and `frontend/src/components/IncidentSimulatorView.tsx` too).

**Problem:** the current header attributes the 57-million-record scale and GPS/bank-detail exposure to the 2022 incident. That data/scale actually belongs to the **2016** Uber breach (attacker used AWS credentials found in a public GitHub repository — not an API/BOLA vector, not MFA fatigue). The 2022 incident is a separate event and must not be merged with it.

**Fix — replace the header with this accurate version (edit wording as needed, keep it factual):**

```
RideX — Deliberately Vulnerable Ride-Sharing API
Inspired by real-world API and access-control failure patterns

This is a synthetic demo application. It is NOT a reproduction of any single
real breach. For research framing, two real, separately-documented incidents
are relevant as CONTRASTING case studies:

  - Uber, 2022: an attacker obtained a contractor's credentials via phishing,
    then bypassed MFA using a fatigue/social-engineering technique (repeated
    push prompts until one was accepted). From there the attacker reached
    internal tools (Slack, internal wikis, cloud consoles). This was a
    BROKEN AUTHENTICATION / excessive-standing-privilege incident, NOT an
    API object/property/function authorization failure. No BOLA/BOPLA/BFLA
    vector was involved. Scope: internal corporate systems, not a customer-
    facing API. (Do not attach a "57 million records" figure to this event.)

  - Uber, 2016: attackers used AWS credentials found in a public GitHub
    repository to access a cloud storage bucket, exposing an estimated
    57 million rider and driver records. This is a CREDENTIAL/SECRETS-
    MANAGEMENT failure, also not a BOLA/BOPLA/BFLA case.

RideX's actual vulnerabilities (BOLA on /rides/{id}, BOPLA via mass-
assignable "role"/"fare_override" fields, BFLA on /admin/* routes) are
modeled on the DOCUMENTED, INDEPENDENTLY-REPORTED breach PATTERNS cited in
Docs/related_work.md (USPS 2018, Panera 2018, T-Mobile 2018-2023, and
public mass-assignment/BFLA bug-bounty writeups) — not on the Uber
incidents. The Uber cases are retained in this project only as contrast
material distinguishing AuthN failures from AuthZ failures.

INTENTIONAL vulnerabilities below exist for AuthzGraph demo/research ONLY.
```

Then grep-check `IncidentSimulatorView.tsx` and any `Docs/*.md` for the same conflation and correct them identically — every mention of the 2022 incident must say "broken authentication / MFA fatigue, not BOLA" and must not carry the 57M figure.

---

## PART B — Make ABAC and MAC Empirically Provable (Highest Priority)

**Problem confirmed by live testing:** running `experiments/ablation.py` currently shows 0% exposure rate when ABAC or MAC is disabled — meaning no attack vector in the harness actually depends on department/region matching (ABAC) or the clearance lattice (MAC). This must be fixed before any ablation numbers go in the paper.

### B.1 — Data model additions (`backend/app/engine/bank_data.py`)

Confirm/add data that makes an ABAC and a MAC violation possible and distinct from BOLA/BOPLA/BFLA:

- At least one `MANAGER` user scoped to Region = South (e.g. Marcus Vance, #301) and at least one resource (an audit report or customer record) explicitly owned/scoped to Region = North, with a *different* manager or no direct owner conflict — so an ABAC violation is "correct role, correct function, correct-ish object type, wrong attribute match" and is NOT reducible to a BOLA ownership check.
- At least one document/record with classification `SECRET` (Level 4) and at least one authenticated user whose clearance is `INTERNAL` (Level 2) or `CONFIDENTIAL` (Level 3) — i.e., a case where RBAC/BOLA/ABAC would all otherwise allow the access, and only the Bell-LaPadula "No Read Up" check blocks it.
- Optional (stronger MAC rigor): add a **"No Write Down"** (star property) scenario too — a SECRET-clearance user attempting to write/downgrade a document to a PUBLIC classification, which real Bell-LaPadula implementations must also block. Implementing both properties (not just No-Read-Up) is a genuine research-quality improvement over the current single-property MAC and should be called out explicitly in the paper as a contribution.

### B.2 — Engine verification (`backend/app/engine/authz_engine.py`, `hybrid_policy.py`)

Confirm (add tests if unclear) that the `disabled_layers` parameter genuinely isolates each check — i.e. disabling `"ABAC"` must not accidentally also bypass the BOLA ownership check for the same request, and vice versa. Add unit tests in `tests/test_engine.py` asserting:
- A same-department, same-region MANAGER request → ALLOW.
- A cross-region MANAGER request → DENY when ABAC active, ALLOW when ABAC disabled (and this must be a case where RBAC/BOLA alone would have allowed it — prove the isolation).
- A clearance-insufficient read of a SECRET document → DENY when MAC active, ALLOW when MAC disabled.
- (If implemented) a "write down" downgrade attempt → DENY when MAC active, ALLOW when MAC disabled.

### B.3 — Benchmark & ablation harness updates

**`backend/experiments/benchmark.py`:** add to `ATTACK_VECTORS`:
```python
ATTACK_VECTORS = [
    "BOLA_SINGLE_OBJECT",
    "BOLA_ENUMERATION",
    "BOPLA_MASS_ASSIGNMENT",
    "BFLA_ADMIN_PROBING",
    "BFLA_VERB_SWITCHING",
    "ABAC_CROSS_REGION",       # NEW
    "ABAC_CROSS_DEPARTMENT",   # NEW
    "MAC_READ_UP_VIOLATION",   # NEW
    "MAC_WRITE_DOWN_VIOLATION" # NEW, if B.1's star-property scenario is implemented
]
```
Each new vector needs a real trial function that fires a real HTTP request built from the B.1 scenario data and records status/latency exactly like the existing vectors — no shortcuts.

**`backend/experiments/ablation.py`:** ensure the per-config exposure-rate computation reports a distinct `ABAC_ER` and `MAC_ER` (and `MAC_WRITE_ER` if applicable) alongside the existing `BOLA/BOPLA/BFLA` columns, so the printed matrix looks like:
```
[CONFIG] ABAC Disabled
   BOLA ER: 0.0% | BOPLA ER: 0.0% | BFLA ER: 0.0% | ABAC ER: 100.0% | MAC ER: 0.0%
[CONFIG] MAC Disabled
   BOLA ER: 0.0% | BOPLA ER: 0.0% | BFLA ER: 0.0% | ABAC ER: 0.0% | MAC ER: 100.0%
```

**Acceptance test for this part:** re-run `python -m experiments.run_all` and confirm every one of the 7 (or 8, with write-down) layer-disabled configs shows >0% exposure on exactly its own attack surface and 0% everywhere else, and the baseline (all layers active) shows 0% across the board. Paste the real console output into the PR/commit description.

---

## PART C — Fix the Paper's Reported Numbers

**File:** `Docs/AuthzGraph_Conference_Paper_Draft.md`

1. Replace the abstract's "90%+ to 0.0%" with the actual measured figure and its 95% confidence interval, pulled from `backend/experiments/results/latest_summary.json` (the field is already computed by `benchmark.py` — you're just not surfacing it). Example target phrasing pattern (fill with real numbers from the latest run): *"a reduction in vulnerability exposure rate from **X.X% (95% CI: [a, b])** in VULNERABLE mode to **0.0%** in SECURE mode across N=... trials per vector, with a mean policy-evaluation latency overhead of **+Y ms**."*
2. Add a small reproducibility script `backend/experiments/report_generator.py` that reads `latest_summary.json` and `latest_ablation_matrix.json` and emits a ready-to-paste Markdown (and optionally LaTeX) results table with means and CIs — this removes manual copy/paste errors between runs and is worth mentioning in the paper's Methodology section as an evidence of reproducibility discipline.
3. Update the Results section table to include the new ABAC/MAC/write-down rows from Part B.

---

## PART D — Rewrite Related Work With Real Citations and an Explicit Differentiation Claim

**File:** `Docs/related_work.md` (currently 33 lines — expand to a real section, ~500–800 words)

Cite and paraphrase (do not copy sentences verbatim) these two directly comparable prior works:

- **Barabanov, A. et al., "Automatic detection of access control vulnerabilities via API specification processing," arXiv:2201.10833 (2022).** Summarize: systematizes IDOR/BOLA attack patterns from a literature/bug-bounty review and proposes an OpenAPI-specification-driven detection algorithm — single-identity, BOLA-only scope.
- **"AuthProbe: Specification-Driven, Multi-Identity Detection of Broken Object-Level Authorization," arXiv:2607.20574 (2026).** Summarize: an open-source, black-box, OpenAPI-driven scanner that logs in as two or more identities and diffs cross-identity object access to catch BOLA/IDOR — multi-identity, still BOLA-only scope, explicitly built for CI gating with an authorized-use-only safeguard.

**Write the differentiation paragraph explicitly** (this is the single most important paragraph in the related-work section — do not bury it):

> Both prior systems are spec-driven and (in AuthProbe's case) multi-identity, matching AuthzGraph's detection methodology for the object-level layer. Neither extends detection to the property level (BOPLA) or function level (BFLA), and neither reports a layer-ablation study establishing which specific enforcement mechanism is responsible for closing which specific vulnerability class. AuthzGraph's contribution is threefold relative to this prior work: (1) a unified, spec-driven, multi-identity detection methodology covering all three authorization layers (object, property, function) rather than object level alone; (2) a formal layer-ablation methodology empirically isolating the necessity of each of RBAC, ABAC, MAC (both Bell-LaPadula properties), BOPLA-whitelisting, and BOLA-ownership checking; and (3) cross-application generalizability validation (Part E) demonstrating the same detection engine transfers to an independently-built target without modification.

Add a small comparison table to the same file:

| Tool | Object-level (BOLA) | Property-level (BOPLA) | Function-level (BFLA) | Multi-identity | Layer-ablation study | Cross-app validation |
|---|---|---|---|---|---|---|
| Barabanov et al. 2022 | Yes | No | No | No | No | Not reported |
| AuthProbe 2026 | Yes | No | No | Yes | No | Not reported |
| **AuthzGraph (this work)** | Yes | Yes | Yes | Yes | Yes | Yes |

---

## PART E — Cross-Application Generalizability Validation

**Goal:** prove the detection engine works on a target it wasn't designed around, not just `target_app/` (RideX).

**Target choice:** use **vAPI** (github.com/roottusk/vapi) as the primary second target — it's a lightweight Flask application with documented BOLA/BFLA-style flaws, much faster to stand up locally than OWASP crAPI's multi-container stack (crAPI needs Postgres + Mongo + Mailhog + multiple services via docker-compose, which risks eating your remaining timeline). List crAPI explicitly as "future work" in the paper rather than attempting it now.

**Implementation:**
1. Add `backend/experiments/targets/vapi_adapter.py`. If vAPI does not ship a machine-readable OpenAPI spec, hand-author a minimal one (`backend/experiments/targets/vapi_openapi.json`) covering just the endpoints you're testing (object-ID path params, any mass-assignable body fields, any admin-only routes) — document this explicitly in the paper as a limitation ("spec hand-authored where the target lacked one; full auto-discovery of undocumented targets is future work"), don't silently pretend it was auto-discovered.
2. Add `backend/experiments/cross_app_validation.py`: runs the same attack-vector logic used against RideX (Part B/original benchmark) against vAPI running on its own local port, and outputs a results table:

   | Target | Vulnerability Class | Endpoint | Detected? | Evidence (status code / diff) |
   |---|---|---|---|---|

3. This becomes a new "External Validity / Cross-Application Generalizability" subsection in the paper's Results section, with the real table from step 2 pasted in — every row must be from an actual local run against actual running vAPI, not simulated.

**Acceptance test:** the script must run end-to-end against a locally-running vAPI instance and produce at least one genuine TRUE POSITIVE detection with real HTTP evidence.

---

## PART F (Optional, if time allows) — Generalize the Engine Itself

If B–E are done with time to spare, this is the highest-leverage architectural upgrade: introduce a `TargetAdapter` abstraction (`backend/app/engine/target_adapter.py`) so the *same* detection engine can be pointed at any REST target given just (a) a base URL and (b) either an OpenAPI spec or a manually declared endpoint descriptor (`object_id_param`, `writable_fields`, `admin_path_prefix`). Refactor RideX and vAPI to both go through this one adapter interface instead of having bespoke per-target logic. This reframes AuthzGraph from "a tool validated on 2 apps" to "a general-purpose authorization fuzzer with 2 validation targets," which is a materially stronger claim for a reviewer. Only do this if A–E are solid first — don't risk breaking passing tests to chase this.

---

## DEFINITION OF DONE — run and report real output for each

```bash
cd backend
python -m pytest -q                          # must show all tests passing, including new B.2 tests
python -m uvicorn main:app --port 8000 &      # start server
python -m experiments.run_all                 # must regenerate summary.json + ablation_matrix.json with real ABAC/MAC ER values
python -m experiments.cross_app_validation    # must show at least 1 real TRUE POSITIVE against vAPI
```

Then confirm by hand:
- `target_app/main.py` header and all `Docs/*.md` mentions of Uber are historically accurate and don't merge 2016/2022.
- `Docs/AuthzGraph_Conference_Paper_Draft.md` abstract/results cite real measured numbers with CI_95, not rounded placeholders.
- `Docs/related_work.md` contains the Barabanov/AuthProbe citations, the differentiation paragraph, and the comparison table.
- The new ABAC/MAC ablation rows show correct, isolated exposure (not 0% everywhere).
- Commit and push to `main` with a commit message summarizing all five parts, and report the final `pytest` count (e.g. "27/27 passing" if 6 new tests were added).
