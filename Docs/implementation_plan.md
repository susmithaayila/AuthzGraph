# Industry-Grade AuthzGraph: Automated REST API Authorization Vulnerability Tester

## Executive Summary & Product Vision

**AuthzGraph** is an enterprise-grade, OpenAPI-driven automated security testing platform designed to discover, demonstrate, and remediate authorization vulnerabilities—specifically **Broken Object Level Authorization (BOLA)**, **Broken Function Level Authorization (BFLA)**, and **Broken Object Property Level Authorization (BOPLA)**—across multi-user REST API microservices.

By combining dynamic API sequence parsing, a stateful multi-user object-ownership graph (NetworkX), cross-user ID substitution, privilege escalation matrix testing, and differential response payload inspection, AuthzGraph replaces manual, error-prone authorization testing with an automated, reproducible security engine.

---

## Key Industry-Level Improvements & Strategic Suggestions

Based on your Zeroth Review presentation and academic objectives, we propose the following enterprise product enhancements to elevate AuthzGraph from a research project into an **industry-leading B2B API Security Product**:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            AUTHZGRAPH ENTERPRISE SUITE                           │
├───────────────────────────────────┬──────────────────────────────────────────────┤
│  1. OpenAPI v3 Dynamic Ingestion  │  Parses endpoints, schemas, parameters,      │
│     & Dependency Mining Engine    │  and infers implicit object relationships.   │
├───────────────────────────────────┼──────────────────────────────────────────────┤
│  2. Dual-User Stateful Object     │  NetworkX-powered ownership graph tracking   │
│     Ownership Graph (Authz-Graph) │  which user owns which resource IDs live.    │
├───────────────────────────────────┼──────────────────────────────────────────────┤
│  3. Multi-Vector Attack Engines   │  • BOLA: Cross-user ID & path substitution   │
│     (BOLA + BFLA + BOPLA)         │  • BFLA: Token swapping & role escalation    │
│                                   │  • BOPLA: Property exposure & mass assignment│
├───────────────────────────────────┼──────────────────────────────────────────────┤
│  4. Differential Payload & Response│  Detects silent data leaks, HTTP 200/403     │
│     Diff Inspection Engine        │  anomalies, and schema variance.             │
├───────────────────────────────────┼──────────────────────────────────────────────┤
│  5. Classic B2B Security UI       │  High-density, professional UI (Snyk/Wiz-    │
│     (Enterprise Design System)    │  inspired, clean Slate theme, zero AI gimmicks)│
├───────────────────────────────────┼──────────────────────────────────────────────┤
│  6. 1-Click crAPI / VAmPI         │  Out-of-the-box dockerized benchmark suite   │
│     Benchmark Suite               │  demonstrating zero-day detection capability.│
└───────────────────────────────────┴──────────────────────────────────────────────┘
```

### 1. Enterprise UI/UX Design System (Classic & Professional, NOT "AI-Generated")
- **Visual Aesthetic**: B2B Cybersecurity Professional (inspired by Datadog, Wiz, Snyk, and SentinelOne).
- **Color Palette**: 
  - Slate Dark Background (`#0B0F17` surface, `#151D2A` cards, `#1E293B` borders)
  - Primary Action / Brand: Crisp Royal Blue (`#2563EB`)
  - Severity Badges: Critical (`#EF4444` Rose), High (`#F97316` Amber), Medium (`#FBBF24` Gold), Low/Clean (`#10B981` Emerald)
- **Typography**: Inter (UI text) + JetBrains Mono (Code, JSON, cURL, Headers).
- **Layout**: High data density, structured tables, interactive graph view, side-by-side HTTP request/response diff viewer, zero flashy rainbow gradients or generic AI decorative icons.

### 2. Intelligent API Dependency & Sequence Resolution
- Automatically parse OpenAPI `paths` and `components/schemas`.
- Automatically chain stateful workflows: run `POST /api/v1/vehicles` as User A, capture the created `vehicle_id`, insert it into the Object Graph, and immediately execute `GET /api/v1/vehicles/{vehicle_id}` as User B.

### 3. Automated Remediation Code Patch Generation
- For every detected vulnerability, provide not only the cURL reproduction command, but also copy-pasteable authorization middleware fixes for **Python (FastAPI / Flask)**, **Node.js (Express)**, and **Java (Spring Boot)**.

---

## User Review Required

> [!IMPORTANT]
> **Scope & Architecture Alignment**: This implementation plan unifies your Zeroth Review PPT slides (O1–O5 objectives, crAPI target, NetworkX graph, BOLA/BFLA/BOPLA testing) with an enterprise B2B product web application. 

> [!NOTE]
> **Tech Stack Choice**:
> - **Backend Engine & API**: Python 3.11+ (FastAPI, NetworkX, OpenAPI-spec-validator, HTTPX async scanner, PyYAML, Pydantic v2).
> - **Frontend Web App**: React 18 + Vite + TypeScript + Tailwind CSS + Lucide Icons + D3.js / React Flow (Interactive Authorization Graph) + Prism / Monaco (Request Diff Viewer).
> - **Benchmark**: Docker Compose setup for target benchmark apps (`crAPI` / `VAmPI`).

---

## Proposed Technical Changes

### Component 1: Core Scanning & Graph Engine (Python Backend)

#### [NEW] [api_parser.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/engine/api_parser.py)
- Ingests OpenAPI v2/v3 (JSON/YAML).
- Extracts endpoints, HTTP methods, route parameters, request body schemas, response schemas, and authentication schemes.
- Identifies potential ID fields (`id`, `user_id`, `vehicle_id`, `account_no`, `uuid`, etc.).

#### [NEW] [object_graph.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/engine/object_graph.py)
- NetworkX directed graph representation of User identities, Session tokens, Resource Types, and dynamic Object IDs.
- Tracks ownership relationships (`UserA -[OWNS]-> Resource_101`).
- Generates substitution pairs for User B cross-user access attempts.

#### [NEW] [bola_engine.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/engine/bola_engine.py)
- Executes stateful setup calls as User A to populate resources.
- Substitutes User A's object IDs into User B's requests.
- Analyzes status codes (e.g., 200 OK instead of 403 Forbidden/404 Not Found) and content ownership to confirm BOLA.

#### [NEW] [bfla_engine.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/engine/bfla_engine.py)
- Maps endpoints by required role/privilege level.
- Executes administrative/high-privilege functions using low-privilege User B tokens.
- Flags unauthorized access to privileged endpoints.

#### [NEW] [bopla_engine.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/engine/bopla_engine.py)
- **Excessive Data Exposure**: Compares returned JSON properties against expected role scope; highlights sensitive leaked fields (`ssn`, `password_hash`, `internal_role`, `credit_card`).
- **Mass Assignment**: Tests sending non-updatable/admin fields in PUT/PATCH requests (`"is_admin": true`).

#### [NEW] [reporter.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/engine/reporter.py)
- Computes CVSS v3.1 severity scores based on vulnerability class and impact.
- Generates structured JSON findings and cURL reproduction commands.
- Synthesizes remediation advice and framework code patches.

#### [NEW] [main.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/main.py)
- FastAPI application serving REST endpoints and WebSockets for real-time scan progress streaming.

---

### Component 2: Professional Enterprise Frontend (React + Vite + TypeScript)

#### [NEW] [App.tsx](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src/App.tsx)
- Application layout with classic sidebar navigation: Dashboard, Target OpenAPI Manager, Live Scanner, Object Graph Explorer, Vulnerabilities & Remediation, Benchmark Suite.

#### [NEW] [Dashboard.tsx](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src/pages/Dashboard.tsx)
- Executive Security Overview: Total Endpoints Monitored, Vulnerabilities Found (BOLA / BFLA / BOPLA breakdown), Risk Index Score, Scan History Timeline, OWASP Risk Radar.

#### [NEW] [GraphExplorer.tsx](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src/pages/GraphExplorer.tsx)
- High-performance D3/Canvas interactive graph visualization.
- Renders Users, Tokens, API Endpoints, and Resource Objects.
- Visualizes attack paths (red directional edges for unauthorized BOLA/BFLA access vectors).

#### [NEW] [ScanConsole.tsx](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src/pages/ScanConsole.tsx)
- Real-time scanner execution console with live log streaming.
- Live HTTP Request/Response inspector.

#### [NEW] [Vulnerabilities.tsx](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src/pages/Vulnerabilities.tsx)
- Finding Cards with CVSS badges, OWASP API category tagging.
- Side-by-side HTTP payload diff viewer (User A Response vs User B Bypass Response).
- 1-click cURL copier & framework remediation snippets (FastAPI, Express, Spring Boot).

#### [NEW] [BenchmarkSuite.tsx](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src/pages/BenchmarkSuite.tsx)
- Pre-loaded crAPI (Completely Ridiculous API) & VAmPI specifications & 1-click test launcher for immediate verification and presentation demos.

---

## Verification Plan

### Automated Verification
1. **Backend Unit Tests**: Verify OpenAPI parser, NetworkX ownership graph construction, and ID substitution engine logic via `pytest`.
2. **Scanner Validation on Benchmark Spec**: Run AuthzGraph engine against crAPI OpenAPI spec and verify detection of all known BOLA, BFLA, and BOPLA endpoints.

### Manual Verification
1. Launch full frontend + backend environment.
2. Verify classic B2B security UI aesthetic (high contrast, crisp typography, responsive panels, clean dark slate mode).
3. Test interactive graph exploration (node selection, attack path highlighting).
4. Run live scan on crAPI target and inspect generated finding reports, cURL repro steps, and code patches.
