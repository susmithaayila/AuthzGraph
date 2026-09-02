"""
AuthzGraph Report Generator
Reads latest_summary.json and latest_ablation_matrix.json and emits
a ready-to-paste Markdown (and optional LaTeX) results table.
Removes manual copy/paste errors between experiment runs.
Usage: python -m experiments.report_generator [--latex]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone


RESULTS_DIR = os.path.join("experiments", "results")
SUMMARY_PATH = os.path.join(RESULTS_DIR, "latest_summary.json")
ABLATION_PATH = os.path.join(RESULTS_DIR, "latest_ablation_matrix.json")


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        print(f"  Run 'python -m experiments.run_all' first to generate results.", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def render_benchmark_markdown(summary: dict) -> str:
    es = summary.get("executive_summary", {})
    vuln_er = es.get("vulnerable_mode_exposure_pct", "N/A")
    sec_er = es.get("secure_mode_exposure_pct", "N/A")
    lat_overhead = es.get("latency_overhead_ms", "N/A")
    fpr = es.get("false_positive_rate_secure_pct", "N/A")
    ts = summary.get("timestamp", "unknown")
    n = summary.get("trials_per_vector", "?")

    lines = [
        f"### Benchmark Results (Generated: {ts})",
        f"*Trials per vector: N={n}*\n",
        "| Metric | VULNERABLE Mode | SECURE Mode |",
        "| :--- | :---: | :---: |",
        f"| **Overall Exposure Rate** | {vuln_er}% | {sec_er}% |",
    ]

    modes = summary.get("modes", {})
    vuln_vectors = modes.get("vulnerable", {}).get("vectors", {})
    sec_vectors = modes.get("secure", {}).get("vectors", {})
    for vector in vuln_vectors:
        v_er = vuln_vectors[vector].get("exposure_rate_pct", "N/A")
        s_er = sec_vectors.get(vector, {}).get("exposure_rate_pct", "N/A")
        v_ci_low = vuln_vectors[vector].get("ci_95_low", "")
        v_ci_high = vuln_vectors[vector].get("ci_95_high", "")
        ci_str = f" (95% CI: [{v_ci_low}, {v_ci_high}])" if v_ci_low != "" else ""
        lines.append(f"| {vector} | {v_er}%{ci_str} | {s_er}% |")

    lat_overhead = es.get("latency_overhead_ms", 0.0)
    lat_str = f"{lat_overhead:+.3f}" if isinstance(lat_overhead, (int, float)) else f"{lat_overhead}"
    lines.append(f"| **Mean Latency Overhead** | — | {lat_str} ms |")
    lines.append(f"| **False Positive Rate** | — | {fpr}% |")

    return "\n".join(lines)


def render_ablation_markdown(ablation: dict) -> str:
    matrix = ablation.get("ablation_matrix", [])
    ts = ablation.get("timestamp", "unknown")
    n = ablation.get("trials_per_config", "?")

    # Discover columns dynamically from first row
    sample = matrix[0] if matrix else {}
    er_keys = [k for k in sample.keys() if k.endswith("_exposure_pct")]
    col_labels = [k.replace("_exposure_pct", "").replace("_", " ").upper() + " ER (%)" for k in er_keys]

    lines = [
        f"### Ablation Matrix (Generated: {ts})",
        f"*Trials per config: N={n}*\n",
        "| Config | Disabled Layer | " + " | ".join(col_labels) + " |",
        "| :--- | :--- | " + " | ".join([":---:"] * len(er_keys)) + " |",
    ]

    for row in matrix:
        config_name = row.get("config_name", "?")
        disabled = row.get("disabled_layer", "None")
        cells = []
        for k in er_keys:
            val = row.get(k, "N/A")
            if isinstance(val, float) and val > 0:
                cells.append(f"**{val}% ⬆️**")
            else:
                cells.append(f"{val}%")
        lines.append(f"| {config_name} | {disabled} | " + " | ".join(cells) + " |")

    return "\n".join(lines)


def render_benchmark_latex(summary: dict) -> str:
    es = summary.get("executive_summary", {})
    ts = summary.get("timestamp", "unknown")
    lat_overhead = es.get("latency_overhead_ms", 0.0)
    lat_str = f"{lat_overhead:+.3f}" if isinstance(lat_overhead, (int, float)) else f"{lat_overhead}"
    lines = [
        f"% AuthzGraph Benchmark Results — Generated {ts}",
        r"\begin{table}[h]",
        r"\centering",
        r"\begin{tabular}{lcc}",
        r"\hline",
        r"\textbf{Metric} & \textbf{VULNERABLE} & \textbf{SECURE} \\",
        r"\hline",
        f"Overall ER & {es.get('vulnerable_mode_exposure_pct', 'N/A')}\\% & {es.get('secure_mode_exposure_pct', 'N/A')}\\% \\\\",
        f"Latency Overhead & --- & {lat_str} ms \\\\",
        f"False Positive Rate & --- & {es.get('false_positive_rate_secure_pct', 'N/A')}\\% \\\\",
        r"\hline",
        r"\end{tabular}",
        r"\caption{AuthzGraph Benchmark Results}",
        r"\label{tab:benchmark}",
        r"\end{table}",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="AuthzGraph Report Generator")
    parser.add_argument("--latex", action="store_true", help="Also emit LaTeX table")
    parser.add_argument("--output", type=str, default=None, help="Save Markdown report to file")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    summary = load_json(SUMMARY_PATH)
    ablation = load_json(ABLATION_PATH)

    md_benchmark = render_benchmark_markdown(summary)
    md_ablation = render_ablation_markdown(ablation)

    report_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    full_report = (
        f"# AuthzGraph Reproducibility Report\n"
        f"*Generated by experiments/report_generator.py at {report_ts}*\n\n"
        + md_benchmark
        + "\n\n---\n\n"
        + md_ablation
    )

    try:
        print(full_report)
    except Exception:
        print(full_report.encode("ascii", "replace").decode("ascii"))

    if args.latex:
        print("\n\n--- LaTeX ---\n")
        try:
            print(render_benchmark_latex(summary))
        except Exception:
            pass

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(full_report)
        print(f"\n[SAVED] Report written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
