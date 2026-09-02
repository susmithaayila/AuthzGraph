"""
Empirical Attack-Success-Rate Benchmark Engine (Section 9.1).
Executes scripted multi-run attack suites against both VULNERABLE and SECURE modes,
measuring exposure rate, latency overhead, and false-positive rate.
"""
import time
from typing import Dict, List, Any
from app.engine.authz_engine import CentralAuthorizationEngine, set_security_mode, get_security_mode
from app.engine.bank_data import SYNTHETIC_USERS, SYNTHETIC_DOCUMENTS

def run_empirical_benchmark(iterations: int = 10) -> Dict[str, Any]:
    """
    Runs N benchmark iterations against both VULNERABLE and SECURE modes.
    Returns metrics table + bar chart dataset.
    """
    original_mode = get_security_mode()

    vuln_metrics = _benchmark_mode("vulnerable", iterations)
    sec_metrics = _benchmark_mode("secure", iterations)

    set_security_mode(original_mode)

    return {
        "title": f"Empirical Attack-Success-Rate Benchmark ({iterations} Runs)",
        "iterations_per_mode": iterations,
        "vulnerable_mode": vuln_metrics,
        "secure_mode": sec_metrics,
        "comparison_summary": {
            "exposure_rate_reduction": f"{vuln_metrics['exposure_rate_pct']}% -> {sec_metrics['exposure_rate_pct']}%",
            "latency_overhead_ms": round(sec_metrics['avg_latency_ms'] - vuln_metrics['avg_latency_ms'], 3),
            "false_positive_rate": f"{sec_metrics['false_positive_rate_pct']}%"
        }
    }


def _benchmark_mode(mode: str, iterations: int) -> Dict[str, Any]:
    set_security_mode(mode)
    alice = SYNTHETIC_USERS[101]

    total_attacks = 0
    successful_attacks = 0
    latencies = []

    # Attack suite: 4 distinct vector types
    for _ in range(iterations):
        # Vector 1: BOLA 10-user enumeration
        for target_id in range(101, 111):
            t0 = time.perf_counter()
            dec = CentralAuthorizationEngine.evaluate_request(
                current_user=alice,
                action="READ",
                resource_type="USER_PROFILE",
                resource_owner_id=target_id,
                endpoint_path=f"/api/v1/bank/users/{target_id}"
            )
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)
            total_attacks += 1
            if dec.decision == "ALLOW" and target_id != 101:
                successful_attacks += 1

        # Vector 2: BOPLA role injection
        t0 = time.perf_counter()
        dec_bopla = CentralAuthorizationEngine.evaluate_request(
            current_user=alice,
            action="UPDATE",
            resource_type="USER_PROFILE",
            resource_owner_id=101,
            requested_properties=["role", "accountBalance"],
            endpoint_path="/api/v1/bank/users/101"
        )
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
        total_attacks += 1
        if dec_bopla.decision == "ALLOW":
            successful_attacks += 1

        # Vector 3: BFLA Admin probing
        t0 = time.perf_counter()
        dec_bfla = CentralAuthorizationEngine.evaluate_request(
            current_user=alice,
            action="READ",
            resource_type="ADMIN_FUNCTION",
            endpoint_path="/api/v1/bank/admin/users"
        )
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
        total_attacks += 1
        if dec_bfla.decision == "ALLOW":
            successful_attacks += 1

    # False Positive check (Legitimate request by owner)
    fp_denials = 0
    fp_tests = iterations * 5
    for _ in range(fp_tests):
        dec_legit = CentralAuthorizationEngine.evaluate_request(
            current_user=alice,
            action="READ",
            resource_type="USER_PROFILE",
            resource_owner_id=101,
            endpoint_path="/api/v1/bank/users/101"
        )
        if dec_legit.decision == "DENY":
            fp_denials += 1

    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    exposure_pct = round((successful_attacks / total_attacks) * 100, 1) if total_attacks else 0.0
    fp_pct = round((fp_denials / fp_tests) * 100, 1) if fp_tests else 0.0

    return {
        "mode": mode,
        "total_attack_attempts": total_attacks,
        "successful_exploits": successful_attacks,
        "exposure_rate_pct": exposure_pct,
        "avg_latency_ms": round(avg_latency, 3),
        "false_positive_rate_pct": fp_pct
    }
