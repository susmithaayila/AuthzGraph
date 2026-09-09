"""
Test suite for new research contribution engines (Empirical Benchmark, Layer-Ablation, Attack Graph, GraphQL).
"""
import pytest
from app.engine.benchmark_engine import run_empirical_benchmark
from app.engine.ablation_engine import run_layer_ablation_study
from app.engine.attack_graph_engine import generate_attack_graph
from app.engine.authz_engine import set_security_mode, get_security_mode

def test_empirical_benchmark():
    res = run_empirical_benchmark(iterations=2)
    assert res["vulnerable_mode"]["exposure_rate_pct"] > 0
    assert res["secure_mode"]["exposure_rate_pct"] == 0.0
    assert "comparison_summary" in res

def test_layer_ablation_study():
    res = run_layer_ablation_study()
    assert res["baseline_all_layers_active"]["protection_rate_pct"] == 100.0
    assert len(res["ablation_matrix"]) == 7

def test_attack_graph_generation():
    set_security_mode("vulnerable")
    g_vuln = generate_attack_graph()
    assert g_vuln["attack_chain_status"] == "VULNERABLE CHAIN EXPLOITABLE"
    
    set_security_mode("secure")
    g_sec = generate_attack_graph()
    assert "PIPELINE DEFENSE ACTIVE" in g_sec["attack_chain_status"]

def test_exact_binomial_ci():
    from experiments.report_generator import exact_binomial_ci
    ci_full = exact_binomial_ci(40, 40)
    ci_zero = exact_binomial_ci(0, 40)
    assert ci_full[0] >= 91.0 and ci_full[1] == 100.0
    assert ci_zero[0] == 0.0 and ci_zero[1] <= 9.0

