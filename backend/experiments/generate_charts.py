"""
Publication Chart Generator for AuthzGraph Research Paper.
Reads benchmark summary and ablation matrix JSON artifacts and generates high-res
figures (PNG + SVG) suitable for inclusion in IEEE/ACM paper templates.
"""
import json
import os
import sys

def generate_paper_charts():
    results_dir = os.path.join("experiments", "results")
    charts_dir = os.path.join(results_dir, "charts")
    os.makedirs(charts_dir, exist_ok=True)

    summary_file = os.path.join(results_dir, "latest_summary.json")
    ablation_file = os.path.join(results_dir, "latest_ablation_matrix.json")

    if not os.path.exists(summary_file) or not os.path.exists(ablation_file):
        print("[WARN] Result files not found. Run benchmark.py and ablation.py first.")
        return

    try:
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("[INFO] matplotlib not installed. Installing matplotlib for paper chart generation...")
        os.system("pip install matplotlib")
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

    # Set publication aesthetic parameters
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.size"] = 10
    plt.rcParams["axes.titlesize"] = 12
    plt.rcParams["axes.labelsize"] = 11

    # -------------------------------------------------------------------------
    # Chart 1: Exposure Rate Comparison (Vulnerable vs Secure)
    # -------------------------------------------------------------------------
    with open(summary_file, "r", encoding="utf-8") as f:
        summary_data = json.load(f)

    vuln_vectors = summary_data["modes"]["vulnerable"]["vectors"]
    sec_vectors = summary_data["modes"]["secure"]["vectors"]

    categories = list(vuln_vectors.keys())
    vuln_er = [vuln_vectors[c]["exposure_rate_pct"] for c in categories]
    sec_er = [sec_vectors[c]["exposure_rate_pct"] for c in categories]

    clean_categories = [c.replace("_", "\n") for c in categories]

    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=300)
    rects1 = ax.bar(x - width/2, vuln_er, width, label="Vulnerable Mode", color="#e63946", edgecolor="black")
    rects2 = ax.bar(x + width/2, sec_er, width, label="AuthzGraph Secure Mode", color="#2a9d8f", edgecolor="black")

    ax.set_ylabel("Vulnerability Exposure Rate (%)")
    ax.set_title("Figure 1: Attack Exposure Rate Comparison (Vulnerable vs AuthzGraph Pipeline)")
    ax.set_xticks(x)
    ax.set_xticklabels(clean_categories)
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)

    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    chart1_png = os.path.join(charts_dir, "figure1_exposure_rate.png")
    chart1_svg = os.path.join(charts_dir, "figure1_exposure_rate.svg")
    plt.savefig(chart1_png)
    plt.savefig(chart1_svg)
    plt.close()
    print(f"[OK] Generated Chart 1: {chart1_png}")

    # -------------------------------------------------------------------------
    # Chart 2: Ablation Matrix Heatmap / Bar Breakdown
    # -------------------------------------------------------------------------
    with open(ablation_file, "r", encoding="utf-8") as f:
        ablation_data = json.load(f)

    matrix = ablation_data["ablation_matrix"]
    config_labels = [row["disabled_layer"] for row in matrix]
    bola_rates = [row["bola_exposure_pct"] for row in matrix]
    bopla_rates = [row["bopla_exposure_pct"] for row in matrix]
    bfla_rates = [row["bfla_exposure_pct"] for row in matrix]

    fig, ax = plt.subplots(figsize=(8.5, 4.5), dpi=300)
    x = np.arange(len(config_labels))
    w = 0.25

    ax.bar(x - w, bola_rates, w, label="BOLA Exposure (%)", color="#d62728", edgecolor="black")
    ax.bar(x, bopla_rates, w, label="BOPLA Exposure (%)", color="#ff7f0e", edgecolor="black")
    ax.bar(x + w, bfla_rates, w, label="BFLA Exposure (%)", color="#1f77b4", edgecolor="black")

    ax.set_ylabel("Vulnerability Class Exposure (%)")
    ax.set_title("Figure 2: Layer-Ablation Study (Impact of Disabling Specific Policy Layers)")
    ax.set_xticks(x)
    ax.set_xticklabels(config_labels, rotation=15)
    ax.set_ylim(0, 115)
    ax.legend(loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    fig.tight_layout()
    chart2_png = os.path.join(charts_dir, "figure2_ablation_study.png")
    chart2_svg = os.path.join(charts_dir, "figure2_ablation_study.svg")
    plt.savefig(chart2_png)
    plt.savefig(chart2_svg)
    plt.close()
    print(f"[OK] Generated Chart 2: {chart2_png}")

    print(f"[SUCCESS] Publication charts successfully generated in: {charts_dir}")


if __name__ == "__main__":
    generate_paper_charts()
