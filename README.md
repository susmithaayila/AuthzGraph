# AuthzGraph 🛡️

**AuthzGraph** is an automated REST API Authorization Vulnerability Tester & Hybrid Access Control Engine. It is designed to discover, analyze, and remediate authorization flaws across multi-user REST API microservices, including:

- **BOLA (Broken Object Level Authorization)** / IDOR
- **BFLA (Broken Function Level Authorization)** / Privilege Escalation
- **BOPLA (Broken Object Property Level Authorization)** / Mass Assignment & Excessive Data Exposure

---

## 🏗️ Architecture & Project Structure

The repository is structured into three main modules:

```
AuthzGraph/
├── backend/            # FastAPI Security Engine & REST API
│   ├── app/            # Engines (API Parser, Object Graph, BOLA/BFLA/BOPLA, Guardrails)
│   ├── main.py         # Entry point for backend server (Port 8000)
│   └── requirements.txt
├── frontend/           # B2B Enterprise Security Dashboard (React + Vite + TypeScript)
│   ├── src/            # Components, pages, and graph visualizer
│   ├── package.json
│   └── vite.config.ts  # Dev server configuration (Port 5173)
├── target_app/         # RideX Benchmark Demo API (Vulnerable Microservice target)
│   ├── main.py         # Target app entry point (Port 8080)
│   ├── dashboard.html  # Live demo target dashboard
│   ├── start.bat       # Windows quick-start launcher
│   └── requirements.txt
└── Docs/               # System implementation plan and design docs
```

---

## ⚡ Quick Start & How to Run

### Prerequisites

- **Python 3.10+** (with `pip`)
- **Node.js 18+** (with `npm`)

---

### Step 1: Start the Target Application (RideX Demo)

In terminal window #1:

```bash
cd target_app
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```
> *Or on Windows, double-click [`target_app/start.bat`](target_app/start.bat).*
> - **RideX Target UI:** [http://localhost:8080/dashboard](http://localhost:8080/dashboard)
> - **RideX OpenAPI Specs:** [http://localhost:8080/docs](http://localhost:8080/docs)

---

### Step 2: Start the AuthzGraph Backend Engine

In terminal window #2:

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
> - **Backend API Docs (Swagger UI):** [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Step 3: Start the AuthzGraph Frontend Dashboard

In terminal window #3:

```bash
cd frontend
npm install
npm run dev
```
> - **AuthzGraph Security Console:** [http://localhost:5173](http://localhost:5173)

---

## 🔬 Research & Empirical Reproducibility Suite

AuthzGraph includes a master experiment runner to reproduce all paper results, ablation matrices, and statistical figures with one command:

```bash
cd backend
python -m experiments.run_all
```

This pipeline automatically executes:
1. **HTTP Benchmark Harness (`experiments/benchmark.py`)**: Attacks the live backend API surface across 5 vector categories in both VULNERABLE and SECURE modes to compute Exposure Rates (ER), P50/P90/P99 Latency Percentiles, and False Positive Rates (FPR).
2. **Layer-Ablation Study (`experiments/ablation.py`)**: Sweeps 7 policy layer configurations (disabling RBAC, BFLA, BOPLA, BOLA, ABAC, MAC independently) to empirically prove layer attribution.
3. **Publication Chart Generator (`experiments/generate_charts.py`)**: Output high-resolution SVG and PNG charts saved under `backend/experiments/results/charts/`.

---

## 🔍 Key Features

- **OpenAPI v2/v3 Dynamic Ingestion**: Automatic endpoint schema parsing and dependency identification.
- **Stateful Object Ownership Graph**: Multi-user resource identity and ownership mapping (`User A -[OWNS]-> Resource 101`).
- **6-Layer Defense-in-Depth Policy Pipeline**: Conjunction of RBAC, BFLA, BOPLA, BOLA, ABAC, and MAC checks for complete mediation.
- **Empirical Layer-Ablation Harness**: Quantitative proof of individual layer necessity against OWASP API1, API3, and API5 vulnerabilities.
- **Target Application Harness**: Integrated RideX benchmark API for security evaluation.

---

## 📜 License

This project is licensed under the MIT License.
