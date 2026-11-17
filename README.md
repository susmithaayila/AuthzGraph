# AuthzGraph: Layered Authorization Engine & Empirical Security Benchmark

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI 0.140.0](https://img.shields.io/badge/FastAPI-0.140.0-009688.svg)](https://fastapi.tiangolo.com/)
[![License: Review Pending](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-lightgrey.svg)]()

> Companion research repository for **"AuthzGraph: Layered Multi-Model Authorization Engine for REST APIs"** (ICCIDSDT 2027).

---

## 📖 Overview

**AuthzGraph** is an authorization mediation and vulnerability detection framework designed to mitigate Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), and Broken Object Property Level Authorization (BOPLA) in RESTful microservices. 

It implements a centralized, multi-model policy engine enforcing **Mandatory Access Control (MAC)**, **Role-Based Access Control (RBAC)**, and **Attribute-Based Access Control (ABAC)** over a stateful object-graph representation of API resources.

---

## 📁 Repository Structure

```
authgraph/
├── backend/
│   ├── app/
│   │   ├── api/             # API routes and demo controllers
│   │   ├── core/            # Security guardrails
│   │   ├── engine/          # AuthzGraph policy engine & graph algorithms
│   │   │   ├── authz_engine.py       # Reference mediator & central authorization engine
│   │   │   ├── bank_data.py          # Synthetic SecureBank dataset and fixtures
│   │   │   ├── hybrid_policy.py      # Formal policy evaluator
│   │   │   ├── attack_graph_engine.py# Graph attack path generator
│   │   │   └── object_graph.py       # Multi-user object relationship graph
│   │   ├── middleware/      # FastAPI authorization interception middleware
│   │   └── routes/          # SecureBank banking endpoints (/bank/...)
│   ├── experiments/         # Empirical evaluation & benchmarking harness
│   │   ├── benchmark.py              # Main 10-vector attack benchmark suite
│   │   ├── ablation.py               # 7-layer exposure ablation study
│   │   ├── run_latency_benchmark.py  # 1,000-trial interleaved latency experiment
│   │   ├── run_cpu_microbenchmark.py # 100,000-eval CPU microbenchmark
│   │   ├── run_task4_traces.py       # Per-stage decision trace extractor
│   │   ├── cross_app_validation.py   # vAPI cross-application validation harness
│   │   ├── targets/
│   │   │   ├── vapi_adapter.py       # vAPI target adapter
│   │   │   └── vapi_openapi.json     # vAPI OpenAPI descriptor
│   │   └── results/                  # Raw evaluation results (CSV, JSON, JSONL)
│   ├── tests/               # Pytest unit and regression test suite (36 tests)
│   └── main.py              # Application entrypoint
├── frontend/                # React / TypeScript interactive visualization dashboard
├── target_app/              # RideX benchmark target application
├── requirements.txt         # Core pinned dependencies (Python 3.12)
├── docker-compose.yml       # Containerized environment deployment
└── README.md                # Project documentation
```

---

## ⚙️ Installation

### Prerequisites
* Python 3.12
* Git
* (Optional) Docker & Docker Compose for containerized targets

### Linux / macOS
```bash
# 1. Clone repository
git clone https://github.com/susmithaayila/AuthzGraph.git
cd AuthzGraph

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Windows (PowerShell)
```powershell
# 1. Clone repository
git clone https://github.com/susmithaayila/AuthzGraph.git
cd AuthzGraph

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Running SecureBank

Start the SecureBank service locally on port 8000:

```bash
python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000
```

* Swagger API documentation is available at: `http://127.0.0.1:8000/docs`
* Health check: `http://127.0.0.1:8000/health`

---

## 🧪 Reproducing Paper Experiments

Ensure the SecureBank server is running on `http://127.0.0.1:8000` before executing the HTTP benchmark scripts.

### 1. Main Attack Benchmark (10 Vectors, Vulnerable vs. Secure Mode)
Runs 20 randomized trials per vector across both unmediated and mediated modes:
```bash
python backend/experiments/benchmark.py --trials 20
```
* Results are saved to: `backend/experiments/results/latest_summary.json` and `backend/experiments/results/latest_raw_trials.jsonl`.

### 2. Layer Ablation Study (7 Configurations)
Sweeps single-control layer ablations to isolate security contribution per layer:
```bash
python backend/experiments/ablation.py --trials 20
```
* Results are saved to: `backend/experiments/results/latest_ablation_matrix.json`.

### 3. Latency Benchmark (1,000 Interleaved Trials)
Runs 100 warm-up requests, followed by 1,000 interleaved trials per mode (2,000 total sequential requests), computing mean, standard deviation, percentiles (P50, P95, P99), and Welch's 95% confidence interval:
```bash
python backend/experiments/run_latency_benchmark.py
```
* Raw latency data is saved to: `backend/experiments/results/latency_benchmark_1000_trials.csv`.

### 4. CPU Microbenchmark (100,000 In-Memory Policy Evaluations)
Times individual policy evaluation calls in memory with zero HTTP network overhead, calibrating `time.perf_counter` timer resolution:
```bash
python backend/experiments/run_cpu_microbenchmark.py
```
* Raw timings are saved to: `backend/experiments/results/cpu_microbenchmark_100k.csv`.

### 5. Decision Traces Execution
Extracts real per-stage decision logs (`ALLOW`/`DENY` and reason text) across the 10 attack vectors and 6 single-control ablations:
```bash
python backend/experiments/run_task4_traces.py
```

### 6. vAPI Cross-Application Validation
To validate generalizability against the third-party vulnerable application [vAPI](https://github.com/roottusk/vapi):

```bash
# In a separate terminal, start vAPI via Docker:
git clone https://github.com/roottusk/vapi
cd vapi
docker compose up -d

# Return to AuthzGraph root and run validation:
python backend/experiments/cross_app_validation.py
```
* Probes tested: BOLA (`GET /api1/user/{id}`) and BFLA (`GET /api5/users`).

---

## 🔒 Synthetic Data & Credentials Notice

> **IMPORTANT:** All user accounts, personal names, account numbers, balances, identification numbers (e.g., Aadhaar / SSN last-4 digits), security clearances, and authorization tokens defined in `backend/app/engine/bank_data.py` and across all tests are **100% synthetic, locally generated test fixtures**. No real customer or production data is contained within this repository.

---

## 📜 Unit & Integration Tests

Run the complete test suite (36 tests):

```bash
python -m pytest backend/tests/ -v
```

---

## 📑 Citation

If you find this research or code useful in your academic work, please cite:

```bibtex
@inproceedings{ayila2027authzgraph,
  title={{AuthzGraph: Layered Multi-Model Authorization Engine for REST APIs}},
  author={Ayila, Susmitha},
  booktitle={Proceedings of the International Conference on Computational Intelligence, Data Science and Security (ICCIDSDT 2027)},
  year={2027}
}
```
