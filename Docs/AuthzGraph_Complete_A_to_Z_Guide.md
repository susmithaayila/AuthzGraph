# AuthzGraph: Comprehensive A-to-Z Technical & Conceptual Architecture Guide

---

## Executive Summary & Vision

**AuthzGraph** is an enterprise-grade, OpenAPI-driven automated security testing platform and hybrid access control engine. It is designed to automatically detect, demonstrate, and remediate authorization vulnerabilities—specifically **Broken Object Level Authorization (BOLA / IDOR)**, **Broken Function Level Authorization (BFLA)**, and **Broken Object Property Level Authorization (BOPLA)**—across modern REST API microservices.

Traditional security scanners rely heavily on static regular expressions or stateless fuzzing, which routinely fail to discover authorization defects. Authorization flaws are inherently **stateful**, **context-dependent**, and **identity-bound**. AuthzGraph solves this by combining:
1. Dynamic OpenAPI v2/v3 Spec Ingestion
2. Stateful Multi-User Object Ownership Graphing (powered by **NetworkX**)
3. A Formal Hybrid Access Control Engine combining **Mandatory Access Control (MAC)**, **Role-Based Access Control (RBAC)**, and **Attribute-Based Access Control (ABAC)**
4. Multi-Vector Attack Simulation Engines (BOLA, BFLA, BOPLA)
5. Automatic Code Remediation Snippet Generation (FastAPI, Express, Spring Boot)

---

## Table of Contents

1. [Architectural Blueprint](#1-architectural-blueprint)
2. [OWASP API Authorization Vulnerability Deep Dive](#2-owasp-api-authorization-vulnerability-deep-dive)
   - [BOLA (Broken Object Level Authorization)](#bola-broken-object-level-authorization)
   - [BFLA (Broken Function Level Authorization)](#bfla-broken-function-level-authorization)
   - [BOPLA (Broken Object Property Level Authorization)](#bopla-broken-object-property-level-authorization)
3. [Stateful Multi-User Object Ownership Graph (NetworkX)](#3-stateful-multi-user-object-ownership-graph-networkx)
4. [Formal Hybrid Access Control Model ($MAC \land (RBAC \lor ABAC)$)](#4-formal-hybrid-access-control-model-mac--rbac--abac)
5. [OpenAPI Dynamic Parsing & Dependency Mining](#5-openapi-dynamic-parsing--dependency-mining)
6. [Multi-Vector Attack Simulation Engines](#6-multi-vector-attack-simulation-engines)
7. [Transparent HTTP Proxy Interceptor & Safety Guardrails](#7-transparent-http-proxy-interceptor--safety-guardrails)
8. [Enterprise B2B Security Console & React Flow Graph Visualizer](#8-enterprise-b2b-security-console--react-flow-graph-visualizer)
9. [RideX Target Benchmark Application](#9-ridex-target-benchmark-application)
10. [Automated Code Patch Remediation Engine](#10-automated-code-patch-remediation-engine)
11. [Operational Runbook & API Reference](#11-operational-runbook--api-reference)

---

## 1. Architectural Blueprint

The AuthzGraph platform operates on a three-tier decoupled architecture:

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AUTHZGRAPH PLATFORM                                    │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌──────────────────────────┐       ┌──────────────────────────┐                         │
│  │   Frontend Dashboard     │       │    RideX Target App      │                         │
│  │  (React + Vite + TS)     │       │  (Vulnerable Benchmark)  │                         │
│  │    http://localhost:5173 │       │   http://localhost:8080  │                         │
│  └────────────┬─────────────┘       └────────────▲─────────────┘                         │
│               │ HTTP / WebSocket                 │ HTTP Attack Payloads                  │
│               ▼                                  │                                       │
│  ┌───────────────────────────────────────────────┴────────────────────────────────────┐  │
│  │                     AuthzGraph Backend Engine (FastAPI)                            │  │
│  │                            http://localhost:8000                                   │  │
│  ├───────────────────────┬──────────────────────────┬────────────────────────────────┤  │
│  │ Dynamic API Parser    │ NetworkX Object Graph    │ Hybrid Access Control Engine   │  │
│  │ (OpenAPI v2/v3)       │ (Identity & Ownership)   │ (MAC + RBAC + ABAC)            │  │
│  ├───────────────────────┼──────────────────────────┼────────────────────────────────┤  │
│  │ BOLA Attack Vector    │ BFLA Attack Vector       │ BOPLA Attack Vector            │  │
│  │ (ID Substitution)     │ (Role Escalation)        │ (Mass Assign / Data Exposure)  │  │
│  ├───────────────────────┼──────────────────────────┼────────────────────────────────┤  │
│  │ Passive HTTP Proxy    │ Safety Guardrails        │ Code Remediation Generator     │  │
│  │ (Port 8888)           │ (Rate Limits & Whitelist)│ (FastAPI, Express, Spring)     │  │
│  └───────────────────────┴──────────────────────────┴────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. OWASP API Authorization Vulnerability Deep Dive

### BOLA (Broken Object Level Authorization)
- **Concept**: Occurs when an API endpoint accepts an object identifier (e.g., `/api/v1/trips/{trip_id}`) without verifying whether the requesting user actually owns or has permission to access that specific object.
- **Attack Path**: User B authenticates, replaces their own `trip_id` with User A's `trip_id`, and accesses User A's private trip history or location data.
- **AuthzGraph Detection**: AuthzGraph tracks User A's created resource IDs in the NetworkX graph and executes cross-user ID substitution attacks using User B's auth token.

### BFLA (Broken Function Level Authorization)
- **Concept**: Occurs when sensitive administrative or privilege-restricted API methods (e.g., `DELETE /api/v1/users/{id}` or `POST /api/v1/admin/roles`) fail to enforce strict role hierarchy checks.
- **Attack Path**: A regular customer user sends a request to an administrative endpoint with their valid user token and successfully executes privileged operations.
- **AuthzGraph Detection**: AuthzGraph enumerates endpoints flagged with administrative permissions and executes them under low-privileged accounts (e.g., `CUSTOMER` or `SUPPORT`).

### BOPLA (Broken Object Property Level Authorization)
- **Concept**: Encompasses two related flaws:
  1. **Excessive Data Exposure**: API responses leak sensitive fields (e.g., `password_hash`, `ssn`, `internal_role`) that the user's role should not see.
  2. **Mass Assignment**: API endpoints accept updates to unmodifiable or internal properties (e.g., `{"role": "ADMIN", "isVerified": true}`) via `PUT`/`PATCH` payloads.
- **AuthzGraph Detection**: AuthzGraph inspects JSON request/response body schemas against a defined dictionary of `PRIVILEGED_PROPERTIES` and flags unauthorized exposures or updates.

---

## 3. Stateful Multi-User Object Ownership Graph (NetworkX)

At the heart of AuthzGraph is the `MultiUserObjectGraph` ([backend/app/engine/object_graph.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/app/engine/object_graph.py)), powered by **NetworkX**.

### Graph Topology
The graph is represented as a Directed Graph $G = (V, E)$:
- **Vertices ($V$)**:
  - `UserIdentity` nodes: `{user_id, username, token, role, clearance}`
  - `ResourceObject` nodes: `{object_id, resource_type, owner_user_id, classification}`
- **Edges ($E$)**:
  - Directed ownership edge: `(User A) -[OWNS]-> (Resource 101)`

```
  [User A: Victim]  ────── (OWNS) ──────► [Resource 101: Trip Record]
         │                                       ▲
         │                                       │ (Unauthorized Target Path)
         ▼                                       │
  [User B: Attacker] ── (Attempts Access) ───────┘
```

### Substitution Pair Generator
To perform accurate BOLA testing, the engine queries out-edges of User A to generate target substitution pairs:
$$\text{Pairs}(A, B) = \{ (o, A) \mid o \in \text{OutEdges}(A, \text{"OWNS"}) \}$$
This guarantees that test requests use real, existing resource IDs created during stateful execution.

---

## 4. Formal Hybrid Access Control Model ($MAC \land (RBAC \lor ABAC)$)

AuthzGraph implements a formal mathematical decision engine ([backend/app/engine/hybrid_policy.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/app/engine/hybrid_policy.py)):

$$\text{Decision}(s, a, o, c) = \text{MAC}(s.\text{clearance}, o.\text{classification}) \land \Big( \text{RBAC}(s.\text{role}, a) \lor \text{ABAC}(s.\text{attrs}, o.\text{attrs}, c) \Big)$$

### 1. MAC (Mandatory Access Control)
Enforces the Bell-LaPadula sensitivity lattice ("No Read Up"):
$$\text{MAC}(s, o) = \text{Level}(s.\text{clearance}) \ge \text{Level}(o.\text{classification})$$
Clearance levels: `PUBLIC` (1) < `INTERNAL` (2) < `CONFIDENTIAL` (3) < `SECRET` (4).

### 2. RBAC (Role-Based Access Control)
Validates whether the subject's role contains the necessary permission in the central role matrix ([backend/app/engine/authz_engine.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/app/engine/authz_engine.py)):
- `CUSTOMER`: Self profile/account/ticket read
- `SUPPORT`: Assigned customer ticket management
- `MANAGER`: Departmental customer/document read
- `ADMIN`: Global permissions, role modification, dashboard access

### 3. ABAC (Attribute-Based Access Control)
Evaluates dynamic runtime context:
- `subject.department == object.department`
- `subject.region == object.region`
- Ownership match (`subject.id == object.owner_id`)

---

## 5. OpenAPI Dynamic Parsing & Dependency Mining

The `OpenAPIParser` ([backend/app/engine/api_parser.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/app/engine/api_parser.py)) parses OpenAPI 2.0/3.0 specifications (JSON or YAML) and extracts:

1. **Endpoints & HTTP Methods**: Route paths, query params, path variables, and body schemas.
2. **Authentication Schemes**: Bearer JWT, API Keys, OAuth2 scopes.
3. **ID Field Discovery**: Automatically scans parameters and schemas for identifier fields using regex patterns (`.*_id`, `id`, `uuid`, `account_no`, `user_id`).
4. **Sequence Chaining**: Identifies creation endpoints (e.g., `POST /api/v1/trips`) to execute setup requests before running read/update attack tests.

---

## 6. Multi-Vector Attack Simulation Engines

AuthzGraph deploys three specialized attack modules:

### 1. BOLA Engine (`bola_engine.py`)
- Executes setup calls as User A (Victim).
- Captures generated object ID in the NetworkX graph.
- Executes `GET`, `PUT`, `DELETE` requests targeting that object ID using User B's token.
- Flags **BOLA Vulnerability** if User B receives HTTP `200 OK` with sensitive payload instead of `403 Forbidden` / `404 Not Found`.

### 2. BFLA Engine (`bfla_engine.py`)
- Maps administrative and sensitive endpoints.
- Replaces high-privilege headers with low-privilege credentials.
- Flags **BFLA Vulnerability** if administrative functions execute successfully under customer tokens.

### 3. BOPLA Engine (`bopla_engine.py`)
- **Mass Assignment**: Injects privileged fields (`"role": "ADMIN"`, `"isVerified": true`, `"balance": 999999`) into update payloads.
- **Excessive Data Exposure**: Compares API response key lists against `PRIVILEGED_PROPERTIES` and flags exposed credentials or internal flags.

---

## 7. Transparent HTTP Proxy Interceptor & Safety Guardrails

### Passive Proxy Interceptor ([backend/app/proxy/proxy_server.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/app/proxy/proxy_server.py))
- Lightweight `asyncio` TCP proxy listening on `0.0.0.0:8888`.
- Captures live browser/mobile app traffic transparently.
- Deduplicates captured endpoints and populates live scan queues automatically.

### Safety Guardrails ([backend/app/core/guardrails.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/backend/app/core/guardrails.py))
- **Target Host Whitelisting**: Restricts attack simulation execution strictly to authorized target hosts (`localhost`, `127.0.0.1`, `crapi.local`).
- **Safe Read-Only Mode**: Restricts requests to `GET`/`HEAD`/`OPTIONS` during dry runs.
- **Rate Limiting**: Enforces maximum requests per second to avoid crashing target servers.

---

## 8. Enterprise B2B Security Console & React Flow Graph Visualizer

The frontend ([frontend/src](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/frontend/src)) provides an intuitive UI:

1. **Executive Security Dashboard**: High-level risk score, vulnerability metrics breakdown (BOLA/BFLA/BOPLA), and real-time scan activity.
2. **Interactive Graph Explorer (`GraphExplorerView.tsx`)**: Rendered using **React Flow** and **Risk Orbit Canvas**, displaying real-time nodes for identities and resources with animated ownership edges.
3. **Attack Lab & Attacker Console**: Live terminal stream showing HTTP request/response diffs, header manipulations, and status code anomalies.
4. **Vulnerability & Remediation Manager**: Provides findings cards with CVSS v3.1 scoring, OWASP API classification, reproduction cURL commands, and copy-pasteable code fixes.

---

## 9. RideX Target Benchmark Application

The repository includes **RideX** ([target_app/main.py](file:///c:/Users/ayila/OneDrive/Desktop/authgraph/target_app/main.py)), a full-featured microservice modeling a ride-hailing app (inspired by famous API breaches):

- **Port**: `8080`
- **Dashboard**: [http://localhost:8080/dashboard](http://localhost:8080/dashboard)
- **Built-in Vulnerabilities**:
  - `GET /api/v1/trips/{trip_id}` → BOLA flaw (allows any user to read any trip)
  - `POST /api/v1/admin/users/role` → BFLA flaw (allows regular users to elevate roles)
  - `PUT /api/v1/users/{user_id}/profile` → BOPLA flaw (allows mass assignment of `is_driver` and `rating`)

---

## 10. Automated Code Patch Remediation Engine

For every detected vulnerability, AuthzGraph generates instant framework-specific remediation snippets:

### FastAPI (Python) Fix
```python
@app.get("/api/v1/trips/{trip_id}")
async def get_trip(trip_id: str, current_user: User = Depends(get_current_user)):
    trip = await db.trips.find_one({"id": trip_id})
    if not trip:
        raise HTTPException(status_code=404, detail="Trip not found")
    
    # Enforce Object-Level Ownership Check (BOLA Remediation)
    if trip["owner_user_id"] != current_user.id and current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied to requested object")
    return trip
```

### Express (Node.js) Fix
```javascript
app.get('/api/v1/trips/:tripId', authenticateToken, async (req, res) => {
  const trip = await Trip.findById(req.params.tripId);
  if (!trip) return res.status(404).json({ error: 'Trip not found' });

  // Enforce Object-Level Ownership Check (BOLA Remediation)
  if (trip.ownerUserId !== req.user.id && req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Access denied to requested object' });
  }
  res.json(trip);
});
```

---

## 11. Operational Runbook & API Reference

### Running the Full System

1. **Target App**:
   ```bash
   cd target_app
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8080 --reload
   ```

2. **Backend Engine**:
   ```bash
   cd backend
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Frontend Dashboard**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

### Backend REST API Summary ([http://localhost:8000/docs](http://localhost:8000/docs))

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/security/mode` | `GET`/`POST` | Toggle security mode (`vulnerable` vs `secure`) |
| `/api/v1/scan/start` | `POST` | Trigger automated BOLA/BFLA/BOPLA scan |
| `/api/v1/graph/state` | `GET` | Export current NetworkX graph as React Flow JSON |
| `/api/v1/logs/decisions` | `GET` | Retrieve live security decision logs |
| `/api/v1/proxy/start` | `POST` | Start transparent HTTP proxy server on port 8888 |
