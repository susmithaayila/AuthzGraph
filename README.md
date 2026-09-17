# SecureShare — Automated REST API Authorization Security Platform

> **SecureShare** is an industry-grade, OpenAPI-driven API security platform that automatically detects **BOLA**, **BFLA**, and **BOPLA** authorization vulnerabilities across multi-user REST API microservices, powered by a Hybrid **MAC + RBAC + ABAC** access control decision engine.

---

## 🔍 What It Does

- **Parses OpenAPI v3 specs** and builds a stateful multi-user object ownership graph (NetworkX)
- **Detects all 3 OWASP API Top-10 authorization vulnerability classes** automatically:
  - `BOLA` (API1:2023) — Broken Object Level Authorization
  - `BFLA` (API5:2023) — Broken Function Level Authorization
  - `BOPLA` (API3:2023) — Broken Object Property Level Authorization
- **Hybrid Policy Engine** — formally evaluates `MAC ∧ (RBAC ∨ ABAC)` at 100K+ decisions/sec
- **Real-Time Risk Orbit** — live radial canvas visualization showing API risk scores
- **CVSS v3.1 Scoring** — deterministic severity scoring for every finding
- **1-Click Remediation** — cURL repros + FastAPI / Express / Spring Boot fix snippets

---

## 🏗️ Architecture

```
OpenAPI Spec → Dependency Graph → Multi-User Object Graph
                                          ↓
                             BOLA / BFLA / BOPLA Engines
                                          ↓
                    Hybrid MAC/RBAC/ABAC Policy Evaluator
                                          ↓
                    CVSS v3.1 Reporter → Risk Orbit UI
```

---

## 🚀 Quick Start

### Option 1 — Docker Compose (Full Stack)
```bash
docker-compose up --build
```
Opens:
- **UI** → http://localhost:80
- **API** → http://localhost:8000
- **crAPI target** → http://localhost:8080
- **VAmPI target** → http://localhost:5000

### Option 2 — Local Development
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

---

## 🧪 Test Suite (36/36 Passing)

```bash
cd backend
python -m pytest -v
```

| Test File | Tests | Coverage |
|---|---|---|
| `test_engine.py` | 5 | Core parser, hybrid policy, normalizer, guardrails |
| `test_abac_mac_isolation.py` | 14 | MAC read-up/write-down, ABAC region isolation, RBAC |
| `test_securebank_authz.py` | 15 | BOLA/BFLA/BOPLA vulnerable vs. secure mode |
| `test_research_contributions.py` | 4 | Scale benchmarks, ablation study, attack graphs |

---

## 🔁 CI/CD Pipeline (GitHub Actions)

| Trigger | Workflow | Action |
|---|---|---|
| Push / PR | `ci.yml` | ruff lint + pytest + npm build |
| Merge to `main` | `docker.yml` | Build & push Docker images to GHCR |

---

## 📁 Project Structure

```
secureshare/
├── .github/workflows/    # GitHub Actions CI/CD
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routes
│   │   ├── core/         # Safety guardrails
│   │   └── engine/       # All detection engines
│   ├── tests/            # 36 pytest tests
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/components/   # 13 React UI components
│   ├── Dockerfile
│   └── nginx.conf
├── target_app/           # Custom vulnerable benchmark API
├── docker-compose.yml
└── Docs/
```

---

## 📚 Base Papers

1. Atlidakis et al., *RESTler: Stateful REST API Fuzzing*, ICSE 2019
2. Atlidakis et al., *Checking Security Properties of Cloud REST APIs*, ICST 2020
3. Servos & Osborn, *Current Research in ABAC*, ACM CSUR 2017

---

## 👩‍💻 Author

**A. Susmitha** — CYS495 Project | Amrita Vishwa Vidyapeetham, Chennai  
Guide: **Dr. K. Venkatesan**
