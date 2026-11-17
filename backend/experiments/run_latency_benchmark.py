"""
Latency Benchmark Script for Task B.
Performs 100 discarded warm-up requests, followed by 1,000 interleaved trials
per mode (unmediated / vulnerable vs mediated / secure) against SecureBank over HTTP.
Uses one sequential httpx client.
Saves raw per-trial latencies to CSV and outputs exact summary statistics with Welch 95% CI.
"""
import csv
import math
import os
import sys
import time
import httpx
from scipy import stats

BASE_URL = "http://127.0.0.1:8000/api/v1"
ALICE_TOKEN = "token_alice"
HEADERS_ALICE = {"Authorization": f"Bearer {ALICE_TOKEN}"}
CSV_OUTPUT = os.path.join("backend", "experiments", "results", "latency_benchmark_1000_trials.csv")

def run_latency_benchmark():
    os.makedirs(os.path.dirname(CSV_OUTPUT), exist_ok=True)
    client = httpx.Client(base_url=BASE_URL, timeout=10.0)

    # 1. Warm-up Phase (100 discarded requests: 50 unmediated, 50 mediated)
    print("[1/3] Running 100 discarded warm-up requests...")
    for i in range(50):
        client.post("/policy/mode", json={"mode": "vulnerable"})
        client.get("/bank/users/101", headers=HEADERS_ALICE)
        client.post("/policy/mode", json={"mode": "secure"})
        client.get("/bank/users/101", headers=HEADERS_ALICE)
    print("      Warm-up complete. All 100 requests discarded.")

    # 2. Main Benchmark (1,000 interleaved trials per mode)
    print("[2/3] Running 1,000 interleaved trials per mode (2,000 measured requests)...")
    unmediated_e2e = []
    unmediated_server = []
    mediated_e2e = []
    mediated_server = []

    rows = []

    for trial in range(1, 1001):
        # Unmediated (vulnerable mode)
        client.post("/policy/mode", json={"mode": "vulnerable"})
        t0 = time.perf_counter()
        r_vuln = client.get("/bank/users/101", headers=HEADERS_ALICE)
        t1 = time.perf_counter()
        lat_vuln_e2e = (t1 - t0) * 1000.0
        srv_hdr = r_vuln.headers.get("X-AuthzEngine-Latency-Ms")
        lat_vuln_srv = float(srv_hdr) if srv_hdr else lat_vuln_e2e

        unmediated_e2e.append(lat_vuln_e2e)
        unmediated_server.append(lat_vuln_srv)
        rows.append({
            "trial_idx": trial,
            "mode": "unmediated",
            "latency_e2e_ms": round(lat_vuln_e2e, 4),
            "latency_server_ms": round(lat_vuln_srv, 4),
            "status_code": r_vuln.status_code
        })

        # Mediated (secure mode)
        client.post("/policy/mode", json={"mode": "secure"})
        t0 = time.perf_counter()
        r_sec = client.get("/bank/users/101", headers=HEADERS_ALICE)
        t1 = time.perf_counter()
        lat_sec_e2e = (t1 - t0) * 1000.0
        srv_hdr = r_sec.headers.get("X-AuthzEngine-Latency-Ms")
        lat_sec_srv = float(srv_hdr) if srv_hdr else lat_sec_e2e

        mediated_e2e.append(lat_sec_e2e)
        mediated_server.append(lat_sec_srv)
        rows.append({
            "trial_idx": trial,
            "mode": "mediated",
            "latency_e2e_ms": round(lat_sec_e2e, 4),
            "latency_server_ms": round(lat_sec_srv, 4),
            "status_code": r_sec.status_code
        })

        if trial % 200 == 0:
            print(f"      Completed {trial}/1,000 trial pairs...")

    # Save to CSV
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["trial_idx", "mode", "latency_e2e_ms", "latency_server_ms", "status_code"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[3/3] Raw per-trial latencies saved to {CSV_OUTPUT}")

    # 3. Statistical Analysis
    def calc_stats(arr):
        n = len(arr)
        mean = sum(arr) / n
        var = sum((x - mean) ** 2 for x in arr) / (n - 1)
        sd = math.sqrt(var)
        s_arr = sorted(arr)
        p50 = s_arr[int(n * 0.50)]
        p95 = s_arr[int(n * 0.95)]
        p99 = s_arr[int(n * 0.99)]
        return {"mean": mean, "sd": sd, "p50": p50, "p95": p95, "p99": p99, "n": n, "var": var}

    def calc_welch_ci(stat_med, stat_unmed):
        m1, v1, n1 = stat_med["mean"], stat_med["var"], stat_med["n"]
        m2, v2, n2 = stat_unmed["mean"], stat_unmed["var"], stat_unmed["n"]
        diff = m1 - m2
        se = math.sqrt(v1 / n1 + v2 / n2)
        # Welch-Satterthwaite df
        df_num = (v1 / n1 + v2 / n2) ** 2
        df_den = ((v1 / n1) ** 2) / (n1 - 1) + ((v2 / n2) ** 2) / (n2 - 1)
        df = df_num / df_den if df_den > 0 else 1.0
        t_crit = stats.t.ppf(0.975, df)
        ci_low = diff - t_crit * se
        ci_high = diff + t_crit * se
        return diff, se, df, ci_low, ci_high

    stats_unmed_e2e = calc_stats(unmediated_e2e)
    stats_med_e2e = calc_stats(mediated_e2e)
    diff_e2e, se_e2e, df_e2e, ci_low_e2e, ci_high_e2e = calc_welch_ci(stats_med_e2e, stats_unmed_e2e)

    stats_unmed_srv = calc_stats(unmediated_server)
    stats_med_srv = calc_stats(mediated_server)
    diff_srv, se_srv, df_srv, ci_low_srv, ci_high_srv = calc_welch_ci(stats_med_srv, stats_unmed_srv)

    print("\n" + "=" * 90)
    print("LATENCY BENCHMARK RESULTS (1,000 Interleaved Trials / Mode, 100 Warm-Up Discarded)")
    print("=" * 90)
    print("END-TO-END HTTP ROUND-TRIP LATENCY (ms):")
    print(f"  Unmediated (Vulnerable) : Mean = {stats_unmed_e2e['mean']:.4f} ms | SD = {stats_unmed_e2e['sd']:.4f} ms | P50 = {stats_unmed_e2e['p50']:.4f} ms | P95 = {stats_unmed_e2e['p95']:.4f} ms | P99 = {stats_unmed_e2e['p99']:.4f} ms")
    print(f"  Mediated (Secure)       : Mean = {stats_med_e2e['mean']:.4f} ms | SD = {stats_med_e2e['sd']:.4f} ms | P50 = {stats_med_e2e['p50']:.4f} ms | P95 = {stats_med_e2e['p95']:.4f} ms | P99 = {stats_med_e2e['p99']:.4f} ms")
    print(f"  Mean Difference (Δ)     : {diff_e2e:+.4f} ms")
    print(f"  Welch 95% CI for Δ      : [{ci_low_e2e:+.4f} ms, {ci_high_e2e:+.4f} ms] (df = {df_e2e:.1f}, SE = {se_e2e:.4f} ms)")
    print("-" * 90)
    print("SERVER-SIDE POLICY EVALUATION LATENCY (X-AuthzEngine-Latency-Ms, ms):")
    print(f"  Unmediated (Vulnerable) : Mean = {stats_unmed_srv['mean']:.4f} ms | SD = {stats_unmed_srv['sd']:.4f} ms | P50 = {stats_unmed_srv['p50']:.4f} ms | P95 = {stats_unmed_srv['p95']:.4f} ms | P99 = {stats_unmed_srv['p99']:.4f} ms")
    print(f"  Mediated (Secure)       : Mean = {stats_med_srv['mean']:.4f} ms | SD = {stats_med_srv['sd']:.4f} ms | P50 = {stats_med_srv['p50']:.4f} ms | P95 = {stats_med_srv['p95']:.4f} ms | P99 = {stats_med_srv['p99']:.4f} ms")
    print(f"  Mean Difference (Δ)     : {diff_srv:+.4f} ms")
    print(f"  Welch 95% CI for Δ      : [{ci_low_srv:+.4f} ms, {ci_high_srv:+.4f} ms] (df = {df_srv:.1f}, SE = {se_srv:.4f} ms)")
    print("=" * 90)

if __name__ == "__main__":
    run_latency_benchmark()
