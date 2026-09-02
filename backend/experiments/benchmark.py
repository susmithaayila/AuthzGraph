"""
AuthzGraph Empirical Research Benchmark Harness.
Attacks the live backend API surface over HTTP, executing multi-trial attack suites
against both VULNERABLE and SECURE modes, generating statistical results artifacts.
"""
import argparse
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
import httpx

DEFAULT_BASE_URL = "http://localhost:8000/api/v1"

# Synthetic user tokens from bank_data.py
ALICE_TOKEN = "token_alice"     # User 101 (CUSTOMER)
BOB_TOKEN = "token_bob"         # User 102 (CUSTOMER)
ADMIN_TOKEN = "token_admin"     # User 401 (ADMIN)

ATTACK_VECTORS = [
    "BOLA_SINGLE_OBJECT",
    "BOLA_ENUMERATION",
    "BOPLA_MASS_ASSIGNMENT",
    "BFLA_ADMIN_PROBING",
    "BFLA_VERB_SWITCHING",
]


def calculate_statistics(latencies: list[float]) -> dict:
    if not latencies:
        return {"mean": 0.0, "std": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0, "ci_95_low": 0.0, "ci_95_high": 0.0}
    
    arr = sorted(latencies)
    n = len(arr)
    mean = sum(arr) / n
    variance = sum((x - mean) ** 2 for x in arr) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(variance)
    
    ci_margin = 1.96 * (std / math.sqrt(n)) if n > 0 else 0.0
    
    p50_idx = min(int(n * 0.50), n - 1)
    p90_idx = min(int(n * 0.90), n - 1)
    p99_idx = min(int(n * 0.99), n - 1)
    
    return {
        "mean": round(mean, 3),
        "std": round(std, 3),
        "p50": round(arr[p50_idx], 3),
        "p90": round(arr[p90_idx], 3),
        "p99": round(arr[p99_idx], 3),
        "ci_95_low": round(max(0.0, mean - ci_margin), 3),
        "ci_95_high": round(mean + ci_margin, 3),
    }


def run_http_benchmark(base_url: str = DEFAULT_BASE_URL, trials_per_vector: int = 40):
    print(f"[INFO] Starting AuthzGraph Research Benchmark Harness")
    print(f"[INFO] Target API: {base_url}")
    print(f"[INFO] Trials per Attack Vector: {trials_per_vector}")
    
    client = httpx.Client(base_url=base_url, timeout=10.0)
    
    # Verify health
    try:
        r = client.get("/health")
        if r.status_code != 200:
            print(f"[ERROR] Backend health check failed: HTTP {r.status_code}")
            sys.exit(1)
        print("[OK] Backend engine health verified.")
    except Exception as e:
        print(f"[ERROR] Could not connect to backend engine at {base_url}: {e}")
        sys.exit(1)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results_dir = os.path.join("experiments", "results", timestamp)
    os.makedirs(results_dir, exist_ok=True)
    latest_dir = os.path.join("experiments", "results")
    
    raw_trials_path = os.path.join(results_dir, "raw_trials.jsonl")
    summary_path = os.path.join(results_dir, "summary.json")
    latest_summary_path = os.path.join(latest_dir, "latest_summary.json")

    raw_file = open(raw_trials_path, "w", encoding="utf-8")
    
    modes = ["vulnerable", "secure"]
    mode_summaries = {}

    headers_alice = {"Authorization": f"Bearer {ALICE_TOKEN}"}

    for mode in modes:
        print(f"\n[MODE] Testing Mode: [{mode.upper()}]")
        client.post("/policy/mode", json={"mode": mode})
        
        mode_trials = []
        vector_stats = {}

        for vector in ATTACK_VECTORS:
            print(f"  --> Running Vector: {vector} ({trials_per_vector} trials)...")
            vector_latencies = []
            exposures = 0
            
            for i in range(trials_per_vector):
                trial_id = f"{mode}_{vector}_{i+1}"
                t0 = time.perf_counter()
                exposed = False
                status_code = 200

                if vector == "BOLA_SINGLE_OBJECT":
                    # Alice (101) attempts to read Bob's (102) user profile
                    res = client.get("/bank/users/102", headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200 and "data" in res.json():
                        exposed = True

                elif vector == "BOLA_ENUMERATION":
                    # Sweep sequential accounts ACC-102 to ACC-106
                    target_user_id = 102 + (i % 5)
                    account_id = f"ACC-{target_user_id}"
                    res = client.get(f"/bank/accounts/{account_id}", headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        acc_data = res.json().get("account", {})
                        if acc_data.get("user_id") != 101:
                            exposed = True

                elif vector == "BOPLA_MASS_ASSIGNMENT":
                    # Alice attempts to update profile and inject 'role': 'ADMIN'
                    payload = {"name": "Alice Smith", "role": "ADMIN", "accountBalance": 999999.0}
                    res = client.patch("/bank/users/101", json=payload, headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200 and res.json().get("updated_user", {}).get("role") == "ADMIN":
                        exposed = True

                elif vector == "BFLA_ADMIN_PROBING":
                    # Alice (CUSTOMER) attempts to hit admin users endpoint
                    res = client.get("/bank/admin/users", headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "BFLA_VERB_SWITCHING":
                    # Alice attempts DELETE on user 102
                    res = client.delete("/bank/admin/users/102", headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                t1 = time.perf_counter()
                latency_ms = (t1 - t0) * 1000.0
                vector_latencies.append(latency_ms)

                if exposed:
                    exposures += 1

                trial_record = {
                    "trial_id": trial_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "mode": mode,
                    "vector": vector,
                    "status_code": status_code,
                    "exposed": exposed,
                    "latency_ms": round(latency_ms, 3),
                }
                raw_file.write(json.dumps(trial_record) + "\n")
                mode_trials.append(trial_record)

            er_pct = round((exposures / trials_per_vector) * 100.0, 1)
            stats = calculate_statistics(vector_latencies)
            stats["exposure_rate_pct"] = er_pct
            stats["trials"] = trials_per_vector
            stats["exposures"] = exposures
            vector_stats[vector] = stats

        # Control Set (Legitimate Traffic to measure False Positives)
        print("  --> Running Control Set (Legitimate Requests)...")
        control_latencies = []
        fp_denials = 0
        control_trials = trials_per_vector

        for i in range(control_trials):
            t0 = time.perf_counter()
            res = client.get("/bank/users/101", headers=headers_alice)
            t1 = time.perf_counter()
            control_latencies.append((t1 - t0) * 1000.0)
            if res.status_code != 200:
                fp_denials += 1

        fpr_pct = round((fp_denials / control_trials) * 100.0, 1)
        control_stats = calculate_statistics(control_latencies)
        control_stats["false_positive_rate_pct"] = fpr_pct
        control_stats["denials"] = fp_denials
        control_stats["trials"] = control_trials

        mode_summaries[mode] = {
            "vectors": vector_stats,
            "control_legitimate": control_stats,
            "overall_exposure_rate_pct": round(
                sum(v["exposure_rate_pct"] for v in vector_stats.values()) / len(vector_stats), 1
            ),
        }

    raw_file.close()

    vuln_er = mode_summaries["vulnerable"]["overall_exposure_rate_pct"]
    sec_er = mode_summaries["secure"]["overall_exposure_rate_pct"]
    
    vuln_mean_lat = sum(v["mean"] for v in mode_summaries["vulnerable"]["vectors"].values()) / len(ATTACK_VECTORS)
    sec_mean_lat = sum(v["mean"] for v in mode_summaries["secure"]["vectors"].values()) / len(ATTACK_VECTORS)
    latency_overhead_ms = round(sec_mean_lat - vuln_mean_lat, 3)

    summary_data = {
        "title": "AuthzGraph Empirical Research Benchmark Summary",
        "timestamp": timestamp,
        "trials_per_vector": trials_per_vector,
        "modes": mode_summaries,
        "executive_summary": {
            "vulnerable_mode_exposure_pct": vuln_er,
            "secure_mode_exposure_pct": sec_er,
            "exposure_reduction_pct": round(vuln_er - sec_er, 1),
            "mean_latency_vulnerable_ms": round(vuln_mean_lat, 3),
            "mean_latency_secure_ms": round(sec_mean_lat, 3),
            "latency_overhead_ms": latency_overhead_ms,
            "false_positive_rate_secure_pct": mode_summaries["secure"]["control_legitimate"]["false_positive_rate_pct"],
        },
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    with open(latest_summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    print(f"\n[SUCCESS] Benchmark Complete!")
    print(f"Summary Artifact Saved: {summary_path}")
    print(f"Latest Summary Shortcut: {latest_summary_path}")
    print(f"Raw Trials Saved: {raw_trials_path}")
    print("\n-----------------------------------------------------------")
    print(f"Vulnerable Exposure Rate: {vuln_er}%")
    print(f"Secure Exposure Rate:     {sec_er}%")
    print(f"Mean Latency Overhead:   +{latency_overhead_ms} ms")
    print(f"False Positive Rate:      {mode_summaries['secure']['control_legitimate']['false_positive_rate_pct']}%")
    print("-----------------------------------------------------------\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthzGraph Research Benchmark Harness")
    parser.add_argument("--url", type=str, default=DEFAULT_BASE_URL, help="Base API URL")
    parser.add_argument("--trials", type=int, default=40, help="Number of trials per attack vector")
    args = parser.parse_args()

    run_http_benchmark(base_url=args.url, trials_per_vector=args.trials)
