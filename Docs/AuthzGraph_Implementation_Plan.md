# AuthzGraph: A Real-Time Hybrid RBAC–ABAC–MAC Authorization Graph for API Misuse Detection

**End-to-end implementation plan — from problem redefinition to a working, demoable product built with Google Antigravity**

> Note: the file you uploaded (`AuthzGraph_Zeroth_Review__1__1_.pptx`) came through as a Microsoft/OneDrive sign-in page HTML file, not your actual slides — likely a failed export/download. I couldn't read your existing content, so this plan is built from your written description plus fresh research. Re-upload the real `.pptx` and I'll tighten this to match your exact wording, diagrams, and scope.

---

## 1. Reframed problem statement

**Current framing (yours):** an authorization-graph project for API security.

**Reframed, sharper version:**

> Most API security tools enforce a *single* access-control model (usually RBAC) and detect misuse only *after the fact*, from logs. Real deployments mix roles, contextual attributes, and hard security classifications simultaneously, and at the scale of thousands of users and hundreds of microservices, static role tables become unauditable. There is no system that (a) unifies RBAC, ABAC, and MAC into one enforceable decision graph, (b) evaluates that graph live as each API call happens, at a user population large enough to stress role/attribute explosion, and (c) gives a security operator a live, glanceable visualization that separates "behaving normally" APIs from "currently being misused" APIs, updating as the situation changes.

This gives you three defensible novelty claims instead of one vague one:
1. **A hybrid RBAC+ABAC+MAC decision model** (not just "using a graph for RBAC").
2. **Scale as a first-class variable** — you explicitly test how the model and detection hold up as user/role/attribute counts grow (1K → 10K → 100K+ synthetic identities), not just correctness on a toy user set.
3. **A real-time, CVE-grounded evaluation on 100 APIs**, with a novel radial/orbit visualization as the operator interface — not just an offline confusion matrix.

---

## 2. The hybrid access-control model (RBAC + ABAC + MAC)

Don't bolt the three together arbitrarily — give each a distinct job, because that's what makes the model defensible in a viva/paper:

| Layer | Role | What it decides |
|---|---|---|
| **MAC** (Mandatory) | Hard, non-negotiable ceiling | Every API resource is labeled with a sensitivity level (Public → Internal → Confidential → Secret) and every subject with a clearance level. MAC enforces a **no-override boundary**: even if RBAC/ABAC would allow it, MAC can block it. Modeled as a lattice (Bell–LaPadula-style "no read up" for data, "no write down" for classification integrity), applied to *API responses and payload fields*, not just endpoints. |
| **RBAC** | Coarse, day-to-day grant | Role → permission → API-endpoint mapping, with role hierarchy (e.g., `support_agent < support_lead < support_admin`). Cheap to evaluate, cheap to audit, this is your baseline "is this call even plausible."|
| **ABAC** | Fine-grained, contextual | Subject attributes (department, device trust score, session risk), object attributes (resource owner, data classification), environmental attributes (time of day, IP reputation, call rate) refine or *restrict* what RBAC allowed. This is where BOLA/BOPLA-style abuse (a valid role calling an endpoint on the *wrong object ID*) gets caught — RBAC alone cannot see this, because RBAC has no notion of "this specific object."|

**Decision function** (this is your core formal contribution — put it in the report explicitly):

```
Decision(subject, action, object, context) =
    MAC_allows(subject.clearance, object.classification)
    AND ( RBAC_allows(subject.role, action, object.type)
          OR ABAC_allows(subject.attrs, action, object.attrs, context) )
```

MAC is a hard AND-gate (a guardrail); RBAC and ABAC form a permissive OR-layer refined against each other. This mirrors how real hybrid models in the literature (e.g., RB-ABAC hybrids, and MAC as a lattice constraint layered over DAC/RBAC) are structured — you're not inventing an unprecedented combination, you're giving a concrete, testable formalization of a known-good pattern, which is exactly what a good capstone project should do.

**Graph representation:** model the whole thing as a property graph — `(User)-[:HAS_ROLE]->(Role)-[:GRANTS]->(Permission)-[:ON]->(APIEndpoint)`, with `(User)-[:HAS_ATTRIBUTE]->(Attribute)` and `(APIEndpoint)-[:CLASSIFIED_AS]->(SensitivityLabel)` as parallel edges. This is what makes real-time evaluation and the visualization possible — a policy decision becomes a graph traversal / reachability query, not a rule interpreter you write from scratch.

---

## 3. Focus on scale (many users) — how to actually test this, not just claim it

- **Synthetic identity generator**: produce 1K / 10K / 100K synthetic users with a Zipfian role distribution (a few common roles, a long tail of edge roles) — real orgs look like this, uniform distributions don't stress the graph the same way.
- **What to measure as scale grows**:
  - Policy decision latency (ms) per call, at each user-population size
  - Graph query cost (Neo4j `EXPLAIN`/`PROFILE` — hops touched, db hits)
  - Memory footprint of the in-memory decision cache
  - Throughput (decisions/sec) the engine sustains before latency degrades
- **What to optimize when it degrades**: precomputed role-closure tables, attribute indexing, decision caching keyed by (role, endpoint, classification) triples with attribute deltas checked only on cache miss.

This turns "more users" from a vague requirement into a graph on your evaluation slide: **latency vs. population size**, with and without your optimization — that's a real, gradable result.

---

## 4. Base paper recommendations

You asked for something in a strong, highly-cited journal that sits close to this work. Three candidates, each doing a different job for you:

1. **Servos & Osborn, "Current Research and Open Problems in Attribute-Based Access Control," ACM Computing Surveys, 2017.** This is the standard, heavily-cited survey covering RBAC, ABAC, and MAC as the three canonical models and the open problems in formalizing and combining them — <cite index="16-1">it positions ABAC as a promising alternative to discretionary access control, mandatory access control, and role-based access control, provides a basic introduction to ABAC, and reviews recent research on formal ABAC models</cite>. **Use this as your primary base paper** — it's the right venue tier (ACM CSUR, top-tier surveys), directly names all three of your models, and gives you a literature skeleton to extend (their "open problems" section is literally a list of gaps you can position your work against — delegation, scalability, hierarchical representation).
2. **"Graph-based formal modeling and implementation of access control policies with automated conflict and redundancy detection," International Journal of Information Security (Springer), 2026.** Very close to your actual method (graph-based access-control modeling), recent, and in a solid Springer security journal — good as a **secondary/methods base paper** for how to justify the graph representation itself.
3. **"API-misuse detection driven by fine-grained API-constraint knowledge graph," ASE 2019 (IEEE/ACM Automated Software Engineering).** <cite index="12-1">This proposes detecting API misuses directly against extracted API-constraint knowledge rather than mined usage-pattern frequency, building a knowledge graph from API documentation</cite> — top-tier software-engineering venue, and it's your closest analog on the *detection* half of the project (they detect misuse via a graph; you detect misuse via an authorization graph). Cite it to justify "graph-based misuse detection" as a legitimate, precedented technique, then differentiate: they detect *call-order/exception* misuse from documentation; you detect *authorization* misuse from live access-control decisions.

Use (1) as your Chapter-2 anchor, (2) and (3) as the two supporting pillars — that's a defensible, well-tiered literature base for a review panel.

---

## 5. The real-time "risk orbit" visualization (your circle idea, formalized)

Your description — a circle where misused APIs sit inside and normal ones sit outside, moving in real time, hoverable for details — is a genuinely good idea; it just needs a name and a precise mechanic so it's buildable and defensible as a UI contribution, not just "a nice animation."

**Mechanic — "Risk Orbit":**
- Every API endpoint in the monitored application is a **point plotted at a radius inversely proportional to its live risk score**. Radius = `R_max × (1 − risk_score)`, so `risk_score ≈ 0` (clean) sits near the outer ring/circumference, and `risk_score → 1` (actively being misused — BOLA attempt, CVE signature match, anomalous rate) is pulled toward the center.
- **Not binary in/out** — a continuous radial gradient reads better than a hard boundary, and it lets you show *escalating* misuse (an endpoint drifting inward over 30 seconds as an attacker probes it) rather than a sudden jump, which is far more convincing in a live demo.
- **Angle** = stable per-endpoint (hashed from service name), so a point's position on the ring doesn't jitter — only its radius moves. This lets an operator build spatial memory of "where their APIs live."
- **Real-time updates**: every API call recomputes that endpoint's risk score (decision-engine verdict + anomaly score) and streams the new radius over WebSocket; the frontend animates the transition (don't snap — tween over ~400ms so the motion itself communicates state change).
- **Hover interaction**: hovering a point shows a tooltip with — endpoint path + method, owning microservice, one-line purpose/description (from your OpenAPI spec `summary` field), current risk score, matched OWASP API Top-10 category if any, matched CVE ID if applicable, last-violation timestamp, and the specific decision-engine layer that fired (MAC block / RBAC deny / ABAC deny).
- **Time dimension**: keep a scrub-back timeline under the orbit (last 5 minutes) so a reviewer can rewind and watch an attack unfold — this is what makes "it should work in real time... along the time changes the api should change" concretely demoable rather than just a live-only view.

Build this with **D3.js or a lightweight Canvas/SVG renderer** driven by React state from a WebSocket stream — this is squarely inside artifact/frontend capability, and later inside your actual product's frontend.

---

## 6. End-to-end system architecture

```
┌─────────────┐   OpenAPI spec ingestion    ┌──────────────────────┐
│  Target App  │ ───────────────────────▶  │  API Inventory Service │
│ (crAPI/VAmPI/│                            │  (parses spec, tags   │
│  your 100    │                            │   endpoints w/ owner, │
│  API corpus) │                            │   sensitivity label)  │
└─────┬────────┘                            └───────────┬──────────┘
      │ live traffic (proxy/gateway capture)             │
      ▼                                                  ▼
┌───────────────────┐   graph writes    ┌──────────────────────────┐
│  Ingestion/Proxy    │ ───────────────▶ │  Authorization Graph (DB) │
│  (Envoy filter / mw)│                  │  Neo4j: Users-Roles-Attrs │
└─────────┬───────────┘                  │  -Permissions-APIs-Labels│
          │ per-call event                └──────────┬───────────────┘
          ▼                                            │ traversal query
┌───────────────────────────┐   verdict + score   ┌────▼─────────────┐
│  Hybrid Decision Engine     │◀───────────────────│ Policy Evaluator  │
│  (MAC gate ∧ (RBAC∨ABAC))   │────────────────────▶│ (graph traversal) │
└──────────┬──────────────────┘                     └───────────────────┘
           │ decision + anomaly score (rule/ML)
           ▼
┌───────────────────┐    WebSocket stream    ┌───────────────────────┐
│  Event/Scoring Bus  │ ─────────────────────▶ │  Frontend: Risk Orbit  │
│  (Kafka/Redis Stream)│                       │  React + D3, hover UI │
└───────────────────┘                          └───────────────────────┘
           │
           ▼
┌───────────────────┐
│  CVE/OWASP Test Harness │  (drives 100-API corpus with labeled attack + benign traffic)
└───────────────────┘
```

---

## 7. The 100-API test corpus and CVE grounding

Don't hand-roll 100 arbitrary endpoints — assemble them from real, citable sources so your evaluation has external validity:

| Source | Approx. endpoints | Why |
|---|---|---|
| **crAPI** (OWASP "Completely Ridiculous API") | ~30 | <cite index="30-1">A deliberately vulnerable API built to demonstrate the ten most critical API security risks</cite>, with realistic microservice structure (shop, community, workshop services) — good for BOLA/BOPLA/mass-assignment cases. |
| **VAmPI** | ~25 | <cite index="30-1">A vulnerable Flask API covering the OWASP API Top 10, with an on/off switch to toggle vulnerable vs. patched behavior</cite> — this toggle is gold for your evaluation: run the *same* endpoint vulnerable and patched, and show your risk orbit reacting only to the vulnerable state. |
| **OWASP Juice Shop (API surface)** | ~20 | Broader OWASP Top Ten coverage beyond API-specific issues, for testing generalization. |
| **Your own synthetic microservice set** | ~25 | Fill the corpus to exactly 100, and this is where you *inject* specific CVE-style patterns (see below) that aren't already in the OSS targets, so you can claim coverage of real CVEs, not just OWASP categories. |

**CVE mapping table (build this explicitly in your report)** — pick 8-10 real, well-documented authorization-related CVEs, and for each: name the CVE, the vulnerability class (BOLA / privilege escalation / auth bypass), and which of your 100 endpoints reproduces the same *pattern* (you're not exploiting the original CVE'd software — you're demonstrating your detector catches the same vulnerability class). Good candidates to research and cite properly: Kubernetes API-server authorization bypass CVEs, Grafana/Zabbix auth-bypass CVEs, and known BOLA disclosures from bug-bounty writeups (T-Mobile API breach, Peloton BOLA). For each, cite the actual CVE record (NVD) rather than a paraphrase from a blog, and keep the mapping honest: "reproduces the same class as CVE-XXXX" not "tests CVE-XXXX directly," unless you're literally running the vulnerable version of that software.

**Labeling protocol:** every one of the 100 endpoints gets: `{owasp_category, cve_analog (nullable), ground_truth_vulnerable (bool), sensitivity_label}`. This is your ground truth for precision/recall.

---

## 8. Evaluation metrics (put these on your results slide)

- **Detection accuracy**: Precision / Recall / F1 for misuse flagging across the 100-API corpus, per OWASP category.
- **Detection latency**: time from malicious call to risk-orbit radius crossing a "flagged" threshold.
- **Scale curve**: decision latency vs. synthetic user population (1K/10K/100K), with/without caching optimization — this directly answers your "more users" requirement.
- **False-positive rate** on purely benign traffic (replay normal user sessions through the same 100 APIs).
- **UI responsiveness**: frame rate / update latency of the orbit under N simultaneous live endpoints.
- **Comparative baseline**: run the same 100-API corpus through a pure-RBAC-only decision engine (no ABAC/MAC) and show it misses the BOLA/BOPLA cases your hybrid model catches — this single comparison is your strongest novelty evidence.

---

## 9. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Graph store | **Neo4j Community** (or Memgraph for lower footprint) | Native property-graph traversal for policy queries |
| Decision engine | Custom Node.js/Python service, optionally embedding **Open Policy Agent (OPA)/Rego** for the ABAC rule layer | OPA gives you a battle-tested policy language instead of hand-rolled rule parsing — cite it as prior art you build on |
| Traffic capture | Reverse proxy middleware (Express/FastAPI middleware for your own corpus; Envoy filter if you want gateway-level capture) | |
| Streaming | Redis Streams (simplest) or Kafka (if you want the "big data" story) | |
| Anomaly scoring | Rule-based rate/sequence checks first; Isolation Forest or a small sequence model as a stretch goal | Keep v1 explainable — a pure ML black box will hurt you in a viva when asked "why was this flagged" |
| Frontend | React + D3.js (or Canvas/WebGL via Three.js if you want particle-like motion) | |
| Test harness | Python scripts driving Locust/pytest against the 100-API corpus, replaying labeled attack + benign sessions | |
| Containerization | Docker Compose for the whole stack (target apps + graph DB + engine + frontend) | Makes the whole thing demoable on one machine |

---

## 10. Building this end-to-end in Google Antigravity

Antigravity (Google's agent-first IDE, built on Gemini 3, with a Manager view for orchestrating multiple parallel agents across editor/terminal/browser) is well suited to a multi-service project like this because each service below is genuinely independent and can be delegated to its own agent thread.

**Setup**
1. Create the repo with a top-level `AGENTS.md` describing your conventions (language choices, folder layout, the hybrid decision formula from §2, the risk-score formula from §5) — Antigravity's agents read this as project-level ground truth, so put your formal model in there verbatim to keep every agent consistent.
2. Scaffold the Docker Compose skeleton first yourself (or with one agent) so every subsequent agent has a running target to plug into.

**Parallel agent breakdown (use the Manager view to run these concurrently):**
- **Agent A — Graph & data model**: builds the Neo4j schema, the synthetic user/role/attribute generator, and seed scripts for 1K/10K/100K populations.
- **Agent B — Decision engine**: implements the MAC/RBAC/ABAC decision function, wraps OPA for the ABAC rule layer, exposes a `/evaluate` endpoint.
- **Agent C — Ingestion/proxy + test corpus**: stands up crAPI/VAmPI/Juice Shop in Docker, writes the OpenAPI-spec ingestion that auto-populates the API inventory graph, builds your synthetic 25-endpoint fill-in set.
- **Agent D — Streaming + scoring**: Redis Streams wiring, anomaly-scoring service, WebSocket server pushing risk-score updates.
- **Agent E — Frontend (Risk Orbit)**: React + D3 visualization, hover tooltips, timeline scrub-back — have this agent use Antigravity's browser tool to self-verify the rendered UI against your spec, screenshot-and-iterate rather than you eyeballing every change.
- **Agent F — CVE test harness**: Locust/pytest scripts replaying labeled attack + benign sessions, produces the precision/recall/latency numbers for §8.

**Workflow discipline that matters for a project like this:**
- Have each agent produce its own PR/diff and artifact (screenshot, test output) rather than merging silently — review each before merging, Antigravity's async feedback model (comment-on-artifact) is built for exactly this.
- Integration is *your* job, not an agent's — after A–D are individually working, run one integration pass wiring the decision engine's verdicts into the streaming layer, then point the frontend at it.
- Don't hand cross-cutting concerns (the actual MAC/RBAC/ABAC formula, the risk-score formula) to two different agents independently — they'll diverge. Keep those two formulas in `AGENTS.md` as the single source of truth.
- Treat Antigravity as a public cloud environment for this project (per Google's own guidance) — don't feed it real production credentials or real user PII; your synthetic user generator exists partly for this reason too.

---

## 11. Suggested timeline (map to your review milestones)

| Phase | Weeks | Deliverable |
|---|---|---|
| Zeroth → First Review | 1–3 | Reframed problem statement, base papers finalized, architecture diagram, hybrid model formalized on paper, Docker skeleton running |
| First → Second Review | 4–7 | Graph + decision engine working end-to-end on a *subset* (crAPI only), synthetic user generator at 1K scale, first version of Risk Orbit rendering static data |
| Second Review → Pre-final | 8–10 | Full 100-API corpus wired in, CVE mapping table complete, scale tests at 10K/100K, real-time WebSocket pipeline live, hover tooltips + timeline scrub-back |
| Pre-final → Final | 11–13 | Baseline (RBAC-only) comparison run, all metrics from §8 collected, polish UI, write-up, demo rehearsal |

---

## 12. What makes this "novel and professional" when you present it

- A **named, formalized decision function** (§2) you can put on a slide and defend line-by-line — reviewers respond well to something they can interrogate.
- A **scale experiment**, not just a scale claim — the latency-vs-population graph is your single best "we actually tested this" artifact.
- A **real CVE/OWASP-grounded corpus** with an honest labeling protocol, not "we made up some vulnerable endpoints."
- A **named UI contribution** (Risk Orbit) with a precise mechanic, not "a nice-looking dashboard."
- A **baseline comparison** (hybrid vs. RBAC-only) that gives you one clean chart proving the hybrid model matters.

---

**Next step:** re-upload the actual `.pptx` (or export it again — the current file is a broken login-page HTML, not your slides) so I can align this plan to your exact existing terminology, diagrams, and whatever scope your panel already approved, and flag anywhere this plan should adjust to match what's already been reviewed.
