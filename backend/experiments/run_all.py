"""
AuthzGraph Master Reproducibility Runner.
Runs the complete empirical benchmark, layer-ablation sweep, and publication chart generation.
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
    print("\n--- STEP 1: Running Empirical Attack-Success-Rate Benchmark ---")
    cmd_benchmark = [sys.executable, "-m", "experiments.benchmark", "--trials", "30"]
    ret = subprocess.call(cmd_benchmark)
    if ret != 0:
        print("[ERROR] Benchmark execution failed.")
        sys.exit(1)

    # Step 2: Run Layer-Ablation Study
    print("\n--- STEP 2: Running Layer-Ablation Study Sweep ---")
    cmd_ablation = [sys.executable, "-m", "experiments.ablation", "--trials", "15"]
    ret = subprocess.call(cmd_ablation)
    if ret != 0:
        print("[ERROR] Ablation study execution failed.")
        sys.exit(1)

    # Step 3: Generate Publication Figures
    print("\n--- STEP 3: Generating Publication Figures & Charts ---")
    cmd_charts = [sys.executable, "-m", "experiments.generate_charts"]
    ret = subprocess.call(cmd_charts)
    if ret != 0:
        print("[ERROR] Chart generation failed.")
        sys.exit(1)

    print("\n==========================================================================")
    print("[SUCCESS] ALL REPRODUCIBILITY EXPERIMENTS COMPLETED SUCCESSFULLY!")
    print("Artifacts generated in backend/experiments/results/")
    print("==========================================================================")

if __name__ == "__main__":
    run_all_experiments()
