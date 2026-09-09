"""
AuthzGraph Empirical Research Benchmark Harness.
Attacks the live backend API surface over HTTP, executing multi-trial attack suites
against both VULNERABLE and SECURE modes with randomized parameters, generating
statistically rigorous result artifacts (Clopper-Pearson CIs, median/IQR latencies,
Wilcoxon signed-rank significance testing).
"""
import argparse
import json
import math
import os
import random
import sys
import time
from datetime import datetime, timezone
import httpx
from scipy.stats import wilcoxon

from experiments.report_generator import exact_binomial_ci

DEFAULT_BASE_URL = "http://localhost:8000/api/v1"

# Synthetic user tokens from bank_data.py
ALICE_TOKEN = "token_alice"          # User 101 (CUSTOMER, South, CONFIDENTIAL clearance)
BOB_TOKEN = "token_bob"              # User 102 (CUSTOMER, North, CONFIDENTIAL clearance)
ADMIN_TOKEN = "token_admin"          # User 401 (ADMIN, SECRET clearance)
MANAGER_NORTH_TOKEN = "token_manager_north"  # User 302 (MANAGER, North region, CONFIDENTIAL)
MANAGER_SOUTH_TOKEN = "token_manager"        # User 301 (MANAGER, South region, CONFIDENTIAL)
MANAGER_EAST_TOKEN = "token_manager_east"    # User 303 (MANAGER, East region, CONFIDENTIAL)
MANAGER_COMM_TOKEN = "token_manager_comm"    # User 304 (MANAGER, Commercial Banking, CONFIDENTIAL)
CHARLIE_TOKEN = "token_charlie"      # User 103 (CUSTOMER, South, INTERNAL clearance)

ATTACK_VECTORS = [
    "BOLA_SINGLE_OBJECT",
    "BOLA_ENUMERATION",
    "BOPLA_MASS_ASSIGNMENT",
    "BFLA_ADMIN_PROBING",
    "BFLA_VERB_SWITCHING",
    "ABAC_CROSS_REGION",
    "ABAC_CROSS_DEPARTMENT",
    "MAC_READ_UP_VIOLATION",
    "MAC_WRITE_DOWN_VIOLATION",
    "RBAC_PERMISSION_DENIED",
]

# Randomization Parameter Pools
CUSTOMER_TARGET_IDS = [102, 103, 104, 105, 106, 107, 108, 109, 110]
PRIVILEGED_FIELDS = ["role", "accountBalance", "internalRiskScore", "isVerified"]

ABAC_REGION_PAIRS = [
    (MANAGER_NORTH_TOKEN, 506, ["North", "South"]),
    (MANAGER_SOUTH_TOKEN, 509, ["South", "North"]),
    (MANAGER_EAST_TOKEN, 506, ["East", "South"]),
]

ABAC_DEPARTMENT_PAIRS = [
    (MANAGER_NORTH_TOKEN, 511, ["Retail Banking", "Commercial Banking"]),
    (MANAGER_SOUTH_TOKEN, 504, ["Retail Banking", "IT Security"]),
    (MANAGER_COMM_TOKEN, 506, ["Commercial Banking", "Retail Banking"]),
]

MAC_READ_UP_PAIRS = [
    (ALICE_TOKEN, 508, ["CONFIDENTIAL", "SECRET"]),
    (CHARLIE_TOKEN, 512, ["INTERNAL", "CONFIDENTIAL"]),
]

MAC_WRITE_DOWN_PAIRS = [
    (ADMIN_TOKEN, 507, ["SECRET", "PUBLIC"]),
    (ADMIN_TOKEN, 504, ["SECRET", "PUBLIC"]),
]

RBAC_ENDPOINTS = [
    "/bank/audit-summary",
    "/bank/compliance-report",
]

BFLA_ADMIN_ROUTES = [
    "/bank/admin/users",
    "/bank/admin/system-logs",
    "/bank/admin/policy-override",
]

BFLA_VERB_SWITCH_CASES = [
    ("DELETE", "/bank/admin/users/102"),
    ("PUT", "/bank/admin/users/102"),
    ("POST", "/bank/admin/users/102/lock"),
]


def calculate_statistics(latencies: list[float]) -> dict:
    if not latencies:
        return {
            "mean": 0.0,
            "std": 0.0,
            "median": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "iqr": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p99": 0.0,
            "ci_95_low": 0.0,
            "ci_95_high": 0.0,
        }

    arr = sorted(latencies)
    n = len(arr)
    mean = sum(arr) / n
    variance = sum((x - mean) ** 2 for x in arr) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(variance)

    ci_margin = 1.96 * (std / math.sqrt(n)) if n > 0 else 0.0

    p25_idx = min(int(n * 0.25), n - 1)
    p50_idx = min(int(n * 0.50), n - 1)
    p75_idx = min(int(n * 0.75), n - 1)
    p90_idx = min(int(n * 0.90), n - 1)
    p99_idx = min(int(n * 0.99), n - 1)

    p25 = round(arr[p25_idx], 3)
    p50 = round(arr[p50_idx], 3)
    p75 = round(arr[p75_idx], 3)
    iqr = round(p75 - p25, 3)

    return {
        "mean": round(mean, 3),
        "std": round(std, 3),
        "median": p50,
        "p50": p50,
        "p25": p25,
        "p75": p75,
        "iqr": iqr,
        "p90": round(arr[p90_idx], 3),
        "p99": round(arr[p99_idx], 3),
        "ci_95_low": round(max(0.0, mean - ci_margin), 3),
        "ci_95_high": round(mean + ci_margin, 3),
    }


def compute_wilcoxon_test(vulnerable_latencies: list[float], secure_latencies: list[float]) -> dict:
    if len(vulnerable_latencies) != len(secure_latencies) or len(vulnerable_latencies) == 0:
        return {"p_value": 1.0, "statistically_significant": False, "median_diff_ms": 0.0}

    diffs = [s - v for v, s in zip(vulnerable_latencies, secure_latencies)]
    sorted_diffs = sorted(diffs)
    med_diff = sorted_diffs[len(sorted_diffs) // 2]

    if all(d == 0 for d in diffs):
        return {"p_value": 1.0, "statistically_significant": False, "median_diff_ms": 0.0}

    try:
        res = wilcoxon(vulnerable_latencies, secure_latencies)
        p_val = float(res.pvalue)
        return {
            "p_value": round(p_val, 5),
            "statistically_significant": p_val < 0.05,
            "median_diff_ms": round(med_diff, 3),
        }
    except Exception as e:
        return {"p_value": 1.0, "statistically_significant": False, "median_diff_ms": round(med_diff, 3), "error": str(e)}


def run_http_benchmark(base_url: str = DEFAULT_BASE_URL, trials_per_vector: int = 40, seed: int = None):
    if seed is None:
        seed = int(time.time() * 1000) % 1000000
    random.seed(seed)

    print(f"[INFO] Starting AuthzGraph Research Benchmark Harness")
    print(f"[INFO] Target API: {base_url}")
    print(f"[INFO] Trials per Attack Vector: {trials_per_vector}")
    print(f"[INFO] Randomization Seed: {seed}")

    client = httpx.Client(base_url=base_url, timeout=10.0)

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
    latest_raw_trials_path = os.path.join(latest_dir, "latest_raw_trials.jsonl")
    summary_path = os.path.join(results_dir, "summary.json")
    latest_summary_path = os.path.join(latest_dir, "latest_summary.json")

    raw_file = open(raw_trials_path, "w", encoding="utf-8")

    # Generate identical sequence of randomized trial parameters across both modes
    trial_plan = []
    for vector in ATTACK_VECTORS:
        for i in range(trials_per_vector):
            params = {}
            if vector == "BOLA_SINGLE_OBJECT":
                params["target_id"] = random.choice(CUSTOMER_TARGET_IDS)
            elif vector == "BOLA_ENUMERATION":
                params["target_id"] = random.choice(CUSTOMER_TARGET_IDS)
            elif vector == "BOPLA_MASS_ASSIGNMENT":
                params["injected_field"] = random.choice(PRIVILEGED_FIELDS)
            elif vector == "BFLA_ADMIN_PROBING":
                params["admin_route"] = random.choice(BFLA_ADMIN_ROUTES)
            elif vector == "BFLA_VERB_SWITCHING":
                method, path = random.choice(BFLA_VERB_SWITCH_CASES)
                params["verb_switch"] = f"{method} {path}"
                params["method"] = method
                params["path"] = path
            elif vector == "ABAC_CROSS_REGION":
                tok, doc_id, reg_pair = random.choice(ABAC_REGION_PAIRS)
                params["token"] = tok
                params["doc_id"] = doc_id
                params["region_pair"] = reg_pair
            elif vector == "ABAC_CROSS_DEPARTMENT":
                tok, doc_id, dept_pair = random.choice(ABAC_DEPARTMENT_PAIRS)
                params["token"] = tok
                params["doc_id"] = doc_id
                params["department_pair"] = dept_pair
            elif vector == "MAC_READ_UP_VIOLATION":
                tok, doc_id, mac_pair = random.choice(MAC_READ_UP_PAIRS)
                params["token"] = tok
                params["doc_id"] = doc_id
                params["mac_pair"] = mac_pair
            elif vector == "MAC_WRITE_DOWN_VIOLATION":
                tok, doc_id, mac_pair = random.choice(MAC_WRITE_DOWN_PAIRS)
                params["token"] = tok
                params["doc_id"] = doc_id
                params["mac_pair"] = mac_pair
            elif vector == "RBAC_PERMISSION_DENIED":
                params["endpoint"] = random.choice(RBAC_ENDPOINTS)

            trial_plan.append((vector, i, params))

    modes = ["vulnerable", "secure"]
    mode_summaries = {}
    server_latencies_by_mode = {"vulnerable": [], "secure": []}

    headers_alice = {"Authorization": f"Bearer {ALICE_TOKEN}"}

    for mode in modes:
        print(f"\n[MODE] Testing Mode: [{mode.upper()}]")
        client.post("/policy/mode", json={"mode": mode})

        vector_stats = {}

        for vector in ATTACK_VECTORS:
            print(f"  --> Running Vector: {vector} ({trials_per_vector} trials)...")
            e2e_latencies = []
            server_latencies = []
            exposures = 0

            vector_trials = [t for t in trial_plan if t[0] == vector]

            for _, i, params in vector_trials:
                trial_id = f"{mode}_{vector}_{i+1}"
                t0 = time.perf_counter()
                exposed = False
                status_code = 200

                if vector == "BOLA_SINGLE_OBJECT":
                    target_id = params["target_id"]
                    res = client.get(f"/bank/users/{target_id}", headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200 and "data" in res.json():
                        exposed = True

                elif vector == "BOLA_ENUMERATION":
                    target_id = params["target_id"]
                    account_id = f"ACC-{target_id}"
                    res = client.get(f"/bank/accounts/{account_id}", headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        acc_data = res.json().get("account", {})
                        if acc_data.get("user_id") != 101:
                            exposed = True

                elif vector == "BOPLA_MASS_ASSIGNMENT":
                    inj_field = params["injected_field"]
                    val = "ADMIN" if inj_field == "role" else (999999.0 if inj_field == "accountBalance" else (0 if inj_field == "internalRiskScore" else False))
                    payload = {"name": "Alice Smith", inj_field: val}
                    res = client.patch("/bank/users/101", json=payload, headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200 and res.json().get("updated_user", {}).get(inj_field) == val:
                        exposed = True

                elif vector == "BFLA_ADMIN_PROBING":
                    route = params["admin_route"]
                    res = client.get(route, headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "BFLA_VERB_SWITCHING":
                    method = params["method"]
                    path = params["path"]
                    res = client.request(method, path, headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "ABAC_CROSS_REGION":
                    tok = params["token"]
                    doc_id = params["doc_id"]
                    res = client.get(f"/bank/documents/{doc_id}", headers={"Authorization": f"Bearer {tok}"})
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "ABAC_CROSS_DEPARTMENT":
                    tok = params["token"]
                    doc_id = params["doc_id"]
                    res = client.get(f"/bank/documents/{doc_id}", headers={"Authorization": f"Bearer {tok}"})
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "MAC_READ_UP_VIOLATION":
                    tok = params["token"]
                    doc_id = params["doc_id"]
                    res = client.get(f"/bank/documents/{doc_id}", headers={"Authorization": f"Bearer {tok}"})
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "MAC_WRITE_DOWN_VIOLATION":
                    tok = params["token"]
                    doc_id = params["doc_id"]
                    res = client.patch(f"/bank/documents/{doc_id}/classify", json={"classification": "PUBLIC"}, headers={"Authorization": f"Bearer {tok}"})
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                elif vector == "RBAC_PERMISSION_DENIED":
                    ep = params["endpoint"]
                    res = client.get(ep, headers=headers_alice)
                    status_code = res.status_code
                    if status_code == 200:
                        exposed = True

                t1 = time.perf_counter()
                latency_e2e_ms = (t1 - t0) * 1000.0

                srv_hdr = res.headers.get("X-AuthzEngine-Latency-Ms")
                if srv_hdr:
                    try:
                        latency_server_ms = float(srv_hdr)
                    except ValueError:
                        latency_server_ms = latency_e2e_ms
                else:
                    latency_server_ms = latency_e2e_ms

                e2e_latencies.append(latency_e2e_ms)
                server_latencies.append(latency_server_ms)
                server_latencies_by_mode[mode].append(latency_server_ms)

                if exposed:
                    exposures += 1

                trial_record = {
                    "trial_id": trial_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "mode": mode,
                    "vector": vector,
                    "status_code": status_code,
                    "exposed": exposed,
                    "trial_params": params,
                    "latency_e2e_ms": round(latency_e2e_ms, 3),
                    "latency_server_ms": round(latency_server_ms, 3),
                    "latency_ms": round(latency_e2e_ms, 3),
                }
                raw_file.write(json.dumps(trial_record) + "\n")

            er_pct = round((exposures / trials_per_vector) * 100.0, 1)
            ci_low, ci_high = exact_binomial_ci(exposures, trials_per_vector)

            stats_e2e = calculate_statistics(e2e_latencies)
            stats_server = calculate_statistics(server_latencies)

            stats = {
                "exposure_rate_pct": er_pct,
                "binomial_ci_95": [ci_low, ci_high],
                "ci_95_low": ci_low,
                "ci_95_high": ci_high,
                "trials": trials_per_vector,
                "exposures": exposures,
                "latency_e2e": stats_e2e,
                "latency_server": stats_server,
                "mean": stats_e2e["mean"],
                "std": stats_e2e["std"],
                "median": stats_e2e["median"],
                "iqr": stats_e2e["iqr"],
                "p50": stats_e2e["p50"],
                "p90": stats_e2e["p90"],
                "p99": stats_e2e["p99"],
            }

            vector_stats[vector] = stats

        # Control Set (Legitimate Traffic to measure False Positives)
        print("  --> Running Control Set (Legitimate Requests)...")
        control_e2e = []
        control_server = []
        fp_denials = 0
        control_trials = trials_per_vector

        for i in range(control_trials):
            t0 = time.perf_counter()
            res = client.get("/bank/users/101", headers=headers_alice)
            t1 = time.perf_counter()
            l_e2e = (t1 - t0) * 1000.0
            srv_hdr = res.headers.get("X-AuthzEngine-Latency-Ms")
            l_srv = float(srv_hdr) if srv_hdr else l_e2e

            control_e2e.append(l_e2e)
            control_server.append(l_srv)
            if res.status_code != 200:
                fp_denials += 1

        fpr_pct = round((fp_denials / control_trials) * 100.0, 1)
        control_ci_low, control_ci_high = exact_binomial_ci(fp_denials, control_trials)

        control_stats = calculate_statistics(control_e2e)
        control_stats["false_positive_rate_pct"] = fpr_pct
        control_stats["binomial_ci_95"] = [control_ci_low, control_ci_high]
        control_stats["denials"] = fp_denials
        control_stats["trials"] = control_trials

        total_exposures_mode = sum(v["exposures"] for v in vector_stats.values())
        total_trials_mode = len(vector_stats) * trials_per_vector
        overall_er_pct = round((total_exposures_mode / total_trials_mode) * 100.0, 1)
        overall_ci_low, overall_ci_high = exact_binomial_ci(total_exposures_mode, total_trials_mode)

        mode_summaries[mode] = {
            "vectors": vector_stats,
            "control_legitimate": control_stats,
            "overall_exposure_rate_pct": overall_er_pct,
            "overall_binomial_ci_95": [overall_ci_low, overall_ci_high],
        }

    raw_file.close()

    # Duplicate raw_trials to latest_raw_trials.jsonl
    with open(raw_trials_path, "r", encoding="utf-8") as f_in, open(latest_raw_trials_path, "w", encoding="utf-8") as f_out:
        f_out.write(f_in.read())

    vuln_er = mode_summaries["vulnerable"]["overall_exposure_rate_pct"]
    sec_er = mode_summaries["secure"]["overall_exposure_rate_pct"]
    vuln_ci = mode_summaries["vulnerable"]["overall_binomial_ci_95"]
    sec_ci = mode_summaries["secure"]["overall_binomial_ci_95"]

    vuln_server_lats = server_latencies_by_mode["vulnerable"]
    sec_server_lats = server_latencies_by_mode["secure"]
    wilcoxon_res = compute_wilcoxon_test(vuln_server_lats, sec_server_lats)

    vuln_mean_lat = sum(v["latency_e2e"]["mean"] for v in mode_summaries["vulnerable"]["vectors"].values()) / len(ATTACK_VECTORS)
    sec_mean_lat = sum(v["latency_e2e"]["mean"] for v in mode_summaries["secure"]["vectors"].values()) / len(ATTACK_VECTORS)
    latency_overhead_ms = round(sec_mean_lat - vuln_mean_lat, 3)

    summary_data = {
        "title": "AuthzGraph Empirical Research Benchmark Summary",
        "timestamp": timestamp,
        "random_seed": seed,
        "trials_per_vector": trials_per_vector,
        "modes": mode_summaries,
        "statistical_tests": {
            "wilcoxon_latency_paired_test": wilcoxon_res,
        },
        "executive_summary": {
            "vulnerable_mode_exposure_pct": vuln_er,
            "vulnerable_mode_binomial_ci_95": vuln_ci,
            "secure_mode_exposure_pct": sec_er,
            "secure_mode_binomial_ci_95": sec_ci,
            "exposure_reduction_pct": round(vuln_er - sec_er, 1),
            "mean_latency_vulnerable_ms": round(vuln_mean_lat, 3),
            "mean_latency_secure_ms": round(sec_mean_lat, 3),
            "latency_overhead_ms": latency_overhead_ms,
            "wilcoxon_p_value": wilcoxon_res.get("p_value"),
            "false_positive_rate_secure_pct": mode_summaries["secure"]["control_legitimate"]["false_positive_rate_pct"],
        },
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    with open(latest_summary_path, "w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)

    lat_sign_str = f"{latency_overhead_ms:+.3f}"
    print(f"\n[SUCCESS] Benchmark Complete!")
    print(f"Summary Artifact Saved: {summary_path}")
    print(f"Latest Summary Shortcut: {latest_summary_path}")
    print(f"Raw Trials Saved: {raw_trials_path}")
    print("\n-----------------------------------------------------------")
    print(f"Vulnerable Exposure Rate: {vuln_er}% (95% CI: {vuln_ci})")
    print(f"Secure Exposure Rate:     {sec_er}% (95% CI: {sec_ci})")
    print(f"Mean Latency Overhead:   {lat_sign_str} ms")
    print(f"Wilcoxon Paired p-value:  {wilcoxon_res.get('p_value')}")
    print(f"False Positive Rate:      {mode_summaries['secure']['control_legitimate']['false_positive_rate_pct']}%")
    print("-----------------------------------------------------------\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthzGraph Research Benchmark Harness")
    parser.add_argument("--url", type=str, default=DEFAULT_BASE_URL, help="Base API URL")
    parser.add_argument("--trials", type=int, default=40, help="Number of trials per attack vector")
    parser.add_argument("--seed", type=int, default=None, help="Randomization seed for reproducibility")
    args = parser.parse_args()

    run_http_benchmark(base_url=args.url, trials_per_vector=args.trials, seed=args.seed)
