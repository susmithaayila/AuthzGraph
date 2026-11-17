"""
CPU Microbenchmark Script for Task C.
1. Calibrates perf_counter overhead over 1,000,000 empty measurement pairs.
2. Pre-builds N=100,000 authorization request parameters in memory.
3. Times each call to CentralAuthorizationEngine.evaluate_request individually.
4. Saves raw timings to CSV.
5. Reports median, mean, P99, timer overhead, and decisions/second (1/mean).
"""
import os
import sys
import time
import csv

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.engine.authz_engine import CentralAuthorizationEngine, set_security_mode, set_active_layers, ALL_VALID_LAYERS
from app.engine.bank_data import SYNTHETIC_USERS

N = 100_000
CSV_OUTPUT = os.path.join("backend", "experiments", "results", "cpu_microbenchmark_100k.csv")

def run_microbenchmark():
    os.makedirs(os.path.dirname(CSV_OUTPUT), exist_ok=True)
    set_security_mode("secure")
    set_active_layers(list(ALL_VALID_LAYERS))

    # Step 1: Calibrate perf_counter timer overhead
    print(f"[1/4] Calibrating perf_counter overhead (1,000,000 empty pairs)...")
    calibration_iterations = 1_000_000
    overhead_samples = []
    for _ in range(calibration_iterations):
        t0 = time.perf_counter()
        t1 = time.perf_counter()
        overhead_samples.append(t1 - t0)

    timer_overhead_s = sum(overhead_samples) / calibration_iterations
    timer_overhead_ns = timer_overhead_s * 1e9
    print(f"      Timer overhead: {timer_overhead_ns:.2f} ns ({timer_overhead_s * 1e6:.4f} µs)")

    # Step 2: Pre-build N=100,000 request objects beforehand
    print(f"[2/4] Pre-building {N:,} request objects in memory...")
    alice = SYNTHETIC_USERS[101]
    
    # Pre-generate parameters across varied legitimate request profiles
    prebuilt_requests = []
    for i in range(N):
        # Mix of read own profile, read own account, read own document
        mod = i % 3
        if mod == 0:
            req = {
                "user": alice,
                "action": "READ",
                "resource_type": "USER_PROFILE",
                "owner_id": 101,
                "endpoint_path": "/api/v1/bank/users/101",
                "required_permission": "PROFILE_READ_SELF",
                "attrs": None,
                "props": None
            }
        elif mod == 1:
            req = {
                "user": alice,
                "action": "READ",
                "resource_type": "ACCOUNT",
                "owner_id": 101,
                "endpoint_path": "/api/v1/bank/accounts/ACC-101",
                "required_permission": "ACCOUNT_READ_SELF",
                "attrs": None,
                "props": None
            }
        else:
            req = {
                "user": alice,
                "action": "READ",
                "resource_type": "DOCUMENT",
                "owner_id": 101,
                "endpoint_path": "/api/v1/bank/documents/505",
                "required_permission": "DOCUMENT_READ_OWN",
                "attrs": {"classification": "PUBLIC"},
                "props": None
            }
        prebuilt_requests.append(req)
    print(f"      {len(prebuilt_requests):,} request parameter tuples pre-allocated.")

    # Warm-up 1,000 evaluations (unrecorded)
    for i in range(1000):
        r = prebuilt_requests[i]
        CentralAuthorizationEngine.evaluate_request(
            current_user=r["user"],
            action=r["action"],
            resource_type=r["resource_type"],
            resource_owner_id=r["owner_id"],
            resource_attributes=r["attrs"],
            endpoint_path=r["endpoint_path"],
            required_permission=r["required_permission"],
        )

    # Step 3: Run timed microbenchmark on each individual call
    print(f"[3/4] Timing each of the {N:,} evaluate_request calls individually...")
    raw_durations_s = []

    for r in prebuilt_requests:
        u = r["user"]
        act = r["action"]
        rt = r["resource_type"]
        oid = r["owner_id"]
        attrs = r["attrs"]
        ep = r["endpoint_path"]
        perm = r["required_permission"]

        t0 = time.perf_counter()
        dec = CentralAuthorizationEngine.evaluate_request(
            current_user=u,
            action=act,
            resource_type=rt,
            resource_owner_id=oid,
            resource_attributes=attrs,
            endpoint_path=ep,
            required_permission=perm,
        )
        t1 = time.perf_counter()
        raw_durations_s.append(t1 - t0)

    # Step 4: Save raw timings to CSV
    print(f"[4/4] Saving raw timings to {CSV_OUTPUT}...")
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["call_idx", "duration_seconds", "duration_microseconds"])
        for idx, dur in enumerate(raw_durations_s, 1):
            writer.writerow([idx, f"{dur:.9f}", f"{dur * 1e6:.4f}"])

    # Compute statistics
    sorted_durations_us = sorted([d * 1e6 for d in raw_durations_s])
    mean_s = sum(raw_durations_s) / N
    mean_us = mean_s * 1e6
    median_us = sorted_durations_us[int(N * 0.50)]
    p99_us = sorted_durations_us[int(N * 0.99)]
    decisions_per_sec = 1.0 / mean_s if mean_s > 0 else 0.0

    print("\n" + "=" * 80)
    print("CPU MICROBENCHMARK RESULTS (N = 100,000 Calls)")
    print("=" * 80)
    print(f"  Sample Size (N)         : {N:,} policy evaluations")
    print(f"  Timer Overhead (ns)     : {timer_overhead_ns:.2f} ns ({timer_overhead_ns / 1000.0:.4f} µs)")
    print(f"  Median Latency          : {median_us:.2f} µs")
    print(f"  Mean Latency            : {mean_us:.2f} µs")
    print(f"  P99 Latency             : {p99_us:.2f} µs")
    print(f"  Decisions per Second    : {decisions_per_sec:,.1f} decisions/sec (1/mean)")
    print(f"  Raw Timings CSV         : {CSV_OUTPUT}")
    print("=" * 80)

if __name__ == "__main__":
    run_microbenchmark()
