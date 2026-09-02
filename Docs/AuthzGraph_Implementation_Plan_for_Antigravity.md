# AuthzGraph — End-to-End Implementation Plan (for Antigravity)

**Purpose of this document:** a complete, code-level build spec to take AuthzGraph from its current state (working scanner engine, zero experimental results) to a submittable research paper for ICCIDSDT 2027. Hand this whole file to the coding agent as its brief. It is organized in execution order — later phases assume earlier phases are done. Do not let the agent skip ahead to Phase 5+ before Phase 2's results file exists; that is the single most common way this kind of project fails to become a paper.

Repository audited: `AuthzGraph-main.zip` (backend: FastAPI, `app/engine/*`, `app/api/routes.py`; frontend: React/Vite; `target_app/`: RideX demo). All file paths below are relative to `backend/`.

---

## 0. The One-Sentence Goal

Produce, with real measured numbers, evidence for this claim:

> *"A layered authorization pipeline (RBAC → BFLA → BOPLA → BOLA → ABAC → MAC) reduces object-, property-, and function-level authorization exposure to near-zero on a synthetic multi-role banking API, and an ablation study shows each layer is responsible for stopping a distinct vulnerability class — no single model (RBAC-only, ABAC-only) closes all three."*

Every phase below exists to produce evidence for or against that sentence. If a task doesn't feed that sentence, it's Tier 3 (see Section 9) — defer it.

---

## 1. Mistakes in the Current Repo, and the Fix for Each

Go through this table before writing any new code. These are concrete defects found by reading the code directly, not guesses.

| # | Mistake | Why it blocks publication | Fix | File(s) |
|---|---|---|---|---|
| 1 | `CURRENT_SECURITY_MODE` is a single global (`"vulnerable"` \| `"secure"`) | Cannot run the ablation study — there is no way to disable *one* layer while keeping the rest active | Add a per-layer toggle (see Section 3) alongside the existing binary mode; keep the binary mode for the main benchmark, add layer-level control for ablation only | `app/engine/authz_engine.py` |
| 2 | No results artifact exists anywhere in the repo | There is currently no Results section possible — a paper cannot cite numbers that don't exist | Build the benchmark harness (Section 4) and commit its output under `experiments/results/` | new: `experiments/` |
| 3 | README claims "Automated Remediation Code Patching for FastAPI/Express/Spring Boot" | Not implemented anywhere in the engine. An overclaim discovered by a reviewer (or an advisor) damages credibility on everything else in the paper | Either remove the claim from README/paper, or scope it down to what's true (e.g. "flags the exact field/line responsible for a denial" — check if `reporter.py` already does this before claiming even that) | `README.md` |
| 4 | Tests are unit-level only (2 files, ~260 lines) — no attack-success test exists | A paper about attack mitigation needs an actual attack-vs-defense test, not just "the function returns the right boolean" | Add `tests/test_attack_benchmark.py` that runs the harness end-to-end on a tiny N and asserts exposure rate is 0% in SECURE mode, >0% in VULNERABLE mode | `backend/tests/` |
| 5 | Synthetic dataset is small: 13 users (10 CUSTOMER, 1 SUPPORT, 1 MANAGER, 1 ADMIN), ~13 accounts | Fine for a demonstration, but if unstated it looks like an oversight rather than a deliberate scope choice | State the dataset size explicitly in the paper's Methodology and Limitations sections; do not silently let a reviewer discover it. Optionally add 10–15 more synthetic users across roles if time allows (cheap, in `bank_data.py`) — more trials via repeated substitution pairs matters more than more users | `app/engine/bank_data.py`, paper §5 & §7 |
| 6 | No related-work content anywhere (code or docs) | The guide's reference list is entirely breach journalism (Krebs, SecurityWeek) — zero prior tools or academic papers. A reviewer's first question is "how is this different from existing OWASP API scanners?" and right now there's no answer | Build `Docs/related_work.md` (Section 6 below) with a real comparison table against RESTler, an OWASP-category scanner (42Crunch or Astra), and at least one academic IDOR-detection paper | `Docs/related_work.md` |
| 7 | No formal threat model document | Expected boilerplate in any security paper; currently only implied informally in the guide | Write `Docs/threat_model.md` (Section 6 below) | `Docs/threat_model.md` |
| 8 | No reproducibility script | A reviewer or advisor should be able to regenerate every number in the paper with one command | Add `experiments/run_all.sh` that runs the target app, backend, and benchmark script in sequence and writes timestamped output | `experiments/run_all.sh` |
| 9 | The guide's breach case studies (Section 6 of the uploaded PDF) are close paraphrases of source reporting in places | Similarity-checking tools (commonly required at ~15% threshold by venues in this tier) will flag close paraphrase even without literal copying | Before pasting any of that guide content into the actual paper, rewrite each case study from scratch in your own words from the primary sources, and cite properly (Krebs on Security, SecurityWeek, etc.) | paper §2 (Background) |
| 10 | No statistical reporting anywhere (single-run thinking) | "It worked once" is not evidence. A benchmark run 1 time proves nothing about a system's actual behavior | Every benchmark and ablation run must report **N (trial count), mean, standard deviation, and a 95% confidence interval** — see Section 5 | `experiments/` |
| 11 | Frontend has a lot of surface area (Attacker Console, Incident Simulator, Risk Orbit Canvas, Benchmark Suite view) relative to what the paper needs | Time spent polishing UI views doesn't produce a single sentence of the Results section. This is the guide's own scope-creep pattern repeating | Freeze frontend work entirely until Phase 2 (benchmark) and Phase 3 (ablation) results exist. The only frontend task worth doing before submission is rendering the two results charts (Section 8) if a live demo is wanted — nothing else | `frontend/` (freeze) |

---

## 2. Required Engine Change: Per-Layer Toggle (build this first)

The ablation study (Section 5) cannot run without this. Today the engine only knows `vulnerable` vs `secure`. Add a second, independent control:

```python
# app/engine/authz_engine.py

ACTIVE_LAYERS: set[str] = {"RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC"}
# All six active by default = current "secure" behavior.

def set_active_layers(layers: set[str]) -> set[str]:
    global ACTIVE_LAYERS
    valid = {"RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC"}
    ACTIVE_LAYERS = layers & valid
    return ACTIVE_LAYERS
```

Then at the top of each existing check function (the RBAC check, the BOLA ownership check, the BOPLA property whitelist check, the BFLA function-boundary check, the ABAC check, the MAC lattice check), add a short-circuit:

```python
if "BOLA" not in ACTIVE_LAYERS:
    # layer disabled for this ablation run — log it, then allow through
    return AuthorizationDecision(decision="ALLOW", reason="layer_disabled_for_ablation", policy="BOLA_PROTECTION", ...)
```

Add one new route for the benchmark harness to drive this:

```
POST /api/policy/active-layers   body: {"layers": ["RBAC","BOPLA","BOLA","ABAC","MAC"]}   # omit BFLA to disable it
GET  /api/policy/active-layers
```

**Important constraint:** this toggle must default to all-six-active on every server restart and must never be reachable from the deployed frontend UI — it exists only for the ablation experiment script to call directly. Keep it out of `AttackerConsoleView`/`IncidentSimulatorView` entirely.

---

## 3. Benchmark Harness Specification (Tier 1 — the paper's core evidence)

### 3.1 What to build

New file: `experiments/benchmark.py` (standalone script, imports the running backend via HTTP, does not import engine internals directly — this keeps the benchmark honest, i.e. it attacks the real API surface, not internal functions).

Reuse existing demo endpoints already in `routes.py` rather than building new attack primitives from scratch:

| Attack type | Endpoint(s) to hit | Method |
|---|---|---|
| BOLA — single object substitution | `/bank/users/{user_id}`, `/bank/accounts/{account_id}` | GET, using another user's ID from a different session token |
| BOLA — enumeration | `/bank/demo/enumerate` (already exists) or sweep `/bank/accounts/{id}` across the full ID range | GET |
| BOPLA — property injection | `/bank/users/{user_id}` with extra JSON fields (`role`, `accountBalance`, `internalRiskScore`, `isVerified`) appended to the legitimate PATCH body | PATCH |
| BFLA — endpoint probing | `/bank/admin/users`, `/bank/admin/audit-logs` called with a CUSTOMER-role token | GET |
| BFLA — verb switching | `DELETE /bank/admin/users/{user_id}` called with a non-ADMIN token | DELETE |

Also run a **legitimate-traffic control set** (each user reading/updating only their own resources) — required to compute the false-positive rate. Skipping this is the most common mistake in this kind of benchmark: without it you can claim 0% exposure but cannot claim the system stays usable.

### 3.2 Trial design

- **N = 200 trials per attack type per mode** (VULNERABLE, SECURE) = 2,000 attack requests total across the 5 attack types, plus a matching 200-trial legitimate-control set per mode.
- 200 is not arbitrary: with a 13-user, 4-role synthetic dataset, 200 trials gives enough repetition across different (attacker, victim, object) triples to report a stable percentage with a tight confidence interval, without needing to inflate the dataset size to make the number look more impressive than the setup actually is.
- Each trial: pick a random (attacker_user, target_object) pair, issue the request, record: HTTP status, whether the response body contains data belonging to someone other than the attacker (exposure), response latency in ms, and which policy layer produced the decision (from the `AuthorizationDecision.policy` field already returned by the engine).

### 3.3 Metrics — exact formulas (use these verbatim in the paper)

| Metric | Formula | What it demonstrates |
|---|---|---|
| **Exposure Rate (ER)** | `successful_unauthorized_accesses / total_attack_attempts` per (attack_type, mode) | Core headline number — should be near 100% in VULNERABLE mode, near 0% in SECURE mode |
| **Latency Overhead** | `(mean_latency_SECURE − mean_latency_VULNERABLE) / mean_latency_VULNERABLE × 100%` | Whether the layered checks cost meaningful performance |
| **False Positive Rate (FPR)** | `legitimate_requests_denied / total_legitimate_requests` in SECURE mode | Whether the fix breaks normal usage — must be reported, a 0% exposure rate with a high FPR is not a good result |
| **Throughput** | decisions/sec — already implemented via `HybridPolicyEvaluator.run_scale_benchmark()`, reuse it, don't rebuild | System-level performance under load |

### 3.4 Output format

Write two files per run, under `experiments/results/<ISO-timestamp>/`:

- `raw_trials.jsonl` — one JSON object per trial: `{trial_id, attack_type, mode, attacker_id, target_id, status_code, exposed: bool, latency_ms, policy_layer, timestamp}`
- `summary.json` — aggregated: for each `(attack_type, mode)` pair, report `{n, exposure_rate, mean, std, ci_95_low, ci_95_high}` (use a normal approximation for the CI: `mean ± 1.96 * std/sqrt(n)`, or a bootstrap with 1,000 resamples if you want it more defensible — either is fine to state in the paper, just say which one)

This `summary.json` is what gets turned into the paper's Results table and Figure 2 (Section 8).

---

## 4. Ablation Study Specification (Tier 2 — the actual novelty claim)

Only start this once Section 3's harness runs cleanly end-to-end and produces a `summary.json` with the expected ER≈100%(vulnerable)/≈0%(secure) pattern. If the base benchmark's numbers look wrong, fix that first — do not run the ablation study on top of a broken baseline.

### 4.1 Configurations

Run the same 5-attack-type suite (Section 3.1) against 7 configurations, N=100 trials per attack type per configuration (smaller N here is fine — this is a systematic sweep, not the headline result):

1. All six layers active (= baseline SECURE)
2. RBAC disabled
3. BFLA disabled
4. BOPLA disabled
5. BOLA disabled
6. ABAC disabled
7. MAC disabled

(All-disabled = baseline VULNERABLE is already covered by Section 3, no need to rerun it here.)

### 4.2 Expected structure of the result (write this table into the paper)

| Layer disabled | BOLA exposure rate | BOPLA exposure rate | BFLA exposure rate |
|---|---|---|---|
| None (baseline) | ~0% | ~0% | ~0% |
| RBAC | ~0% | ~0% | **↑ high** |
| BFLA | ~0% | ~0% | **↑ high** |
| BOPLA | ~0% | **↑ high** | ~0% |
| BOLA | **↑ high** | ~0% | ~0% |
| ABAC | depends — report actual | depends — report actual | depends — report actual |
| MAC | depends — report actual | depends — report actual | depends — report actual |

The point of this table is to show each layer's specific job. **If a layer's removal changes nothing** (exposure stays ~0% even with it disabled), that is itself a finding worth reporting honestly — it means another layer is compensating, or the layer is redundant for this dataset. Do not hide a null result; report it and discuss why in the paper's Discussion section. A null result you explain is more credible to a reviewer than a suspiciously perfect table.

### 4.3 Statistical note

This is a deterministic policy engine, not a stochastic ML system — for a fixed configuration the exposure rate should not vary much between runs (unlike, say, a neural network's accuracy). If repeated runs of the *same* configuration produce noticeably different exposure rates, that indicates a bug (e.g. a race condition or a caching issue in the engine), not natural variance — investigate before reporting. Latency, unlike exposure rate, will naturally vary between runs — that's the one metric where std/CI reporting genuinely matters here.

---

## 5. Required Writing Artifacts (Tier 1 — no code needed, do these in parallel with Section 3)

### 5.1 `Docs/threat_model.md`

Must state explicitly, in this order:
1. **Attacker capabilities**: has a valid low-privilege (CUSTOMER-role) account; can intercept and modify their own traffic via browser DevTools or a local proxy; cannot access source code, infrastructure, or other users' credentials.
2. **Attacker goals**: horizontal data access (read another user's records), privilege escalation (self-grant elevated role/fields), vertical function access (reach admin-only endpoints).
3. **Out of scope**: network-level attacks (MITM on TLS), supply-chain compromise, physical access, credential theft/phishing, denial of service.

### 5.2 `Docs/related_work.md`

A real comparison table — this is the single most important missing artifact in the current guide. Minimum entries:

| Tool/paper | Detects BOLA | Detects BOPLA | Detects BFLA | Dynamic OpenAPI ingestion | Layered/hybrid policy model | Ablation-validated layer attribution |
|---|---|---|---|---|---|---|
| RESTler (Atlidakis et al., ICSE 2019) | partial (via fuzzing) | no | no | yes | no | no |
| 42Crunch / commercial API scanners | yes | partial | yes | yes | no (rule-based, not layered RBAC/ABAC/MAC) | no |
| Astra (open-source API pentest tool) | yes | partial | yes | yes | no | no |
| Academic IDOR-detection papers *(search for and cite 1–2 real ones — do not fabricate citations)* | yes | rarely | rarely | varies | no | no |
| **AuthzGraph (this work)** | yes | yes | yes | yes | yes (RBAC+ABAC+MAC) | **yes — this is the contribution** |

Have Antigravity (or you, manually) search for and verify 1–2 real academic IDOR/BOLA-detection papers to fill that row properly — do not let an agent invent a citation that doesn't exist; a fabricated reference is grounds for outright rejection if caught, which is worse than a thin related-work section.

### 5.3 Limitations paragraph (goes in paper §7, Discussion)

State plainly: single-tenant scope, synthetic 13-user dataset, no production traffic, deterministic policy engine (not evaluated against adaptive/adversarial attackers), REST-only (no GraphQL). This reads as rigor, not weakness — write it before a reviewer has to ask for it.

---

## 6. What NOT to Build Before Submission (Tier 3 — explicitly deferred)

Every item below is real, useful engineering work, but none of it produces a sentence for the Results section. Do not let the agent pick these up "since it's already building things" — that is exactly how the original guide's scope-creep happened.

- GraphQL extension (guide §9.5)
- Anomaly-detection add-on (guide §9.4) — this is a second paper's worth of work (needs its own precision/recall evaluation) and does not belong bolted onto this one
- Attacker Console UI polish, Risk Orbit Canvas visuals, Incident Simulator theatrics
- Automated remediation code-patch generation (the README's current overclaim — either cut the claim or build a minimal true version *after* submission, not before)
- Expanding the synthetic dataset beyond ~25–30 users (more trials via repeated substitution pairs matters more than more users, per Section 3.2)

---

## 7. Paper Structure — Section-by-Section, With the Exact Artifact Each One Needs

Do not start writing a section until its artifact column exists.

| § | Section | Length | Required artifact before writing |
|---|---|---|---|
| — | Abstract | 150–250 words | Must state the actual headline number, e.g. *"...reduced exposure rate from X% to Y% across N=2,000 trials..."* — never write the abstract with placeholder numbers |
| 1 | Introduction | 0.75–1 page | None — can draft early, but revise the contribution bullets once results exist |
| 2 | Background & Related Work | 1–1.5 pages | `Docs/related_work.md` (§5.2), rewritten breach case studies in your own words (§1, mistake #9) |
| 3 | Threat Model | 0.5 page | `Docs/threat_model.md` (§5.1) |
| 4 | System Architecture | 1–1.5 pages | Architecture diagram (Section 8) |
| 5 | Methodology | 1 page | Section 3 (trial design) + explicit statement of dataset size (13 users, 4 roles) |
| 6 | Results | 1–1.5 pages | `experiments/results/.../summary.json` (§3.4) + ablation table (§4.2) + Figures 2–3 (Section 8) |
| 7 | Discussion & Limitations | 0.5–0.75 page | Any null results from ablation (§4.2) + limitations paragraph (§5.3) |
| 8 | Mitigation Recommendations | 0.5 page | Distilled from the six-layer design — practitioner checklist |
| 9 | Conclusion & Future Work | 0.25 page | List Tier 3 items (Section 6) explicitly as future work — this is the correct home for them, not the current submission |
| — | References | — | Real citations only — see §5.2 warning on fabricated references |

---

## 8. Figures and Tables to Generate

1. **Fig 1 — System architecture diagram**: request flow through AuthN → RBAC → BFLA → BOPLA → BOLA → ABAC → MAC → response. A static diagram, no code needed beyond drawing it.
2. **Fig 2 — Exposure rate bar chart**: x-axis = attack type (5 categories), grouped bars for VULNERABLE vs SECURE mode, y-axis = exposure rate %. Generated directly from `summary.json` (§3.4).
3. **Fig 3 — Latency overhead bar chart**: SECURE vs VULNERABLE mean latency per attack type, with error bars from the std/CI in `summary.json`.
4. **Table 1** — Related work comparison (§5.2).
5. **Table 2** — Ablation results (§4.2).
6. **Table 3** — RBAC role-permission matrix (already exists conceptually in `authz_engine.py`'s `ROLE_PERMISSIONS` — just format it for the paper).

Frontend work, if any live demo is wanted for the conference presentation, should be limited to rendering Fig 2 and Fig 3 in the existing `BenchmarkSuiteView` component — nothing else needs new UI.

---

## 9. Order of Operations for Antigravity

Execute in this order. Each phase has a clear "done" condition — do not proceed to the next phase until it's met.

1. **Fix mistakes #1, #4, #8 from Section 1** (engine layer-toggle, attack-benchmark test stub, reproducibility script skeleton). *Done when:* `POST /api/policy/active-layers` works and a trivial N=5 benchmark run produces a `summary.json`.
2. **Build the full benchmark harness (Section 3).** *Done when:* `experiments/results/<timestamp>/summary.json` exists with N=200 per attack type per mode, and the VULNERABLE-mode exposure rate is meaningfully higher than SECURE-mode for all 5 attack types. If it isn't, that's a bug in the engine or the harness — fix before proceeding.
3. **Write `Docs/threat_model.md` and `Docs/related_work.md` (Section 5)** — can be done in parallel with step 2 by a human, or immediately after by the agent.
4. **Run the ablation study (Section 4).** *Done when:* the 7-configuration table (§4.2) is filled with real numbers, including any honest null results.
5. **Generate Figures 2–3 and Tables 1–2** from the JSON artifacts.
6. **Write the paper (Section 7 order)**, using only real numbers from steps 2 and 4.
7. **Advisor review** (Dr. Deepak K) — get sign-off before submission; confirm authorship order with your capstone teammate.
8. **Submit to ICCIDSDT 2027** once its CFP/template is published — check `manuu.edu.in/ICCIDSDT2027` for the template and page-limit requirements before final formatting, and run a similarity check if the venue requires one (recent MANUU conferences in this series have required <15% similarity).

---

## 10. Final Checklist Before Submission

- [ ] Every number in the paper traces to a file in `experiments/results/`
- [ ] No claim in the paper is unsupported by §1's mistake table (i.e., the README overclaims have been removed or scoped down, and the paper doesn't repeat them)
- [ ] Related work table cites real, verifiable prior work — no fabricated citations
- [ ] Breach case studies are rewritten in original words, not close paraphrases of the guide/source articles
- [ ] Limitations section explicitly states the 13-user synthetic dataset and single-tenant scope
- [ ] Abstract states an actual measured result, not a placeholder
- [ ] Authorship order and advisor sign-off confirmed
- [ ] Venue template/page limit/similarity threshold checked once ICCIDSDT 2027's CFP is live
