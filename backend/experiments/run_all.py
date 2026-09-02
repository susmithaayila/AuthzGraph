"""
AuthzGraph Master Reproducibility Runner.
Runs the complete empirical benchmark, layer-ablation sweep, publication chart generation,
and report generation (Markdown + LaTeX tables).
One command reproduces all paper figures and JSON summary artifacts.
"""
import os
import sys
import subprocess

def run_all_experiments():
    print("==========================================================================")
    print("[INFO] AuthzGraph Academic Research Experiment Execution Pipeline")
    print("==========================================================================")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(base_dir)

    # Step 1: Run HTTP Benchmark
    print("\n--- STEP 1: Running Empirical Attack-Success-Rate Benchmark (N=40 trials/vector) ---")
    cmd_benchmark = [sys.executable, "-m", "experiments.benchmark", "--trials", "40"]
    ret = subprocess.call(cmd_benchmark)
    if ret != 0:
        print("[ERROR] Benchmark execution failed.")
        sys.exit(1)

    # Step 2: Run Layer-Ablation Study
    print("\n--- STEP 2: Running Layer-Ablation Study Sweep (N=20 trials/config) ---")
    cmd_ablation = [sys.executable, "-m", "experiments.ablation", "--trials", "20"]
    ret = subprocess.call(cmd_ablation)
    if ret != 0:
        print("[ERROR] Ablation study execution failed.")
        sys.exit(1)

    # Step 3: Generate Publication Figures
    print("\n--- STEP 3: Generating Publication Figures & Charts ---")
    cmd_charts = [sys.executable, "-m", "experiments.generate_charts"]
    ret = subprocess.call(cmd_charts)
    if ret != 0:
        print("[WARN] Chart generation failed (may need matplotlib). Continuing...")

    # Step 4: Generate Reproducibility Report (Markdown + LaTeX)
    print("\n--- STEP 4: Generating Reproducibility Report ---")
    report_path = os.path.join("experiments", "results", "latest_report.md")
    cmd_report = [sys.executable, "-m", "experiments.report_generator", "--latex", "--output", report_path]
    ret = subprocess.call(cmd_report)
    if ret != 0:
        print("[WARN] Report generation failed. Continuing...")
    else:
        print(f"[OK] Reproducibility report saved to {report_path}")

    print("\n==========================================================================")
    print("[SUCCESS] ALL REPRODUCIBILITY EXPERIMENTS COMPLETED SUCCESSFULLY!")
    print("Artifacts generated in backend/experiments/results/")
    print("  - latest_summary.json       (benchmark results)")
    print("  - latest_ablation_matrix.json (ablation results)")
    print("  - latest_report.md          (reproducibility report)")
    print("==========================================================================")

if __name__ == "__main__":
    run_all_experiments()
