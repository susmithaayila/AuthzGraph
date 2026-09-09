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
    plt.rcParams["font.size"] = 9
    plt.rcParams["axes.titlesize"] = 11
    plt.rcParams["axes.labelsize"] = 10

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

    clean_categories = [c.replace("_", " ") for c in categories]

    x = np.arange(len(categories))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 5.2), dpi=300)
    rects1 = ax.bar(x - width/2, vuln_er, width, label="Vulnerable Mode", color="#e63946", edgecolor="black")
    rects2 = ax.bar(x + width/2, sec_er, width, label="AuthzGraph Secure Mode", color="#2a9d8f", edgecolor="black")

    ax.set_ylabel("Vulnerability Exposure Rate (%)", fontweight="bold")
    ax.set_title("Figure 1: Attack Exposure Rate Comparison (Vulnerable vs AuthzGraph Pipeline)", fontweight="bold", pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(clean_categories, rotation=30, ha="right", fontsize=8, fontweight="bold")
    ax.set_ylim(0, 118)
    ax.legend(loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, fontweight="bold")

    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width()/2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, fontweight="bold")

    fig.tight_layout()
    chart1_png = os.path.join(charts_dir, "figure1_exposure_rate.png")
    chart1_svg = os.path.join(charts_dir, "figure1_exposure_rate.svg")
    plt.savefig(chart1_png)
    plt.savefig(chart1_svg)
    plt.close()
    print(f"[OK] Generated Chart 1: {chart1_png}")

    # -------------------------------------------------------------------------
    # Chart 2: Full 7x7 Layer-Ablation Matrix Heatmap
    # -------------------------------------------------------------------------
    with open(ablation_file, "r", encoding="utf-8") as f:
        ablation_data = json.load(f)

    matrix = ablation_data["ablation_matrix"]
    row_labels = [row["config_name"] for row in matrix]

    col_keys = [
        ("rbac_exposure_pct", "RBAC ER"),
        ("bfla_exposure_pct", "BFLA ER"),
        ("bopla_exposure_pct", "BOPLA ER"),
        ("bola_exposure_pct", "BOLA ER"),
        ("abac_exposure_pct", "ABAC ER"),
        ("mac_exposure_pct", "MAC Read ER"),
        ("mac_write_exposure_pct", "MAC Write ER"),
    ]
    col_labels = [c[1] for c in col_keys]

    data_matrix = []
    for row in matrix:
        r_vals = [float(row.get(c[0], 0.0)) for c in col_keys]
        data_matrix.append(r_vals)

    data_arr = np.array(data_matrix)

    fig, ax = plt.subplots(figsize=(9.5, 5.5), dpi=300)
    im = ax.imshow(data_arr, cmap="YlOrRd", vmin=0, vmax=100, aspect="auto")

    ax.set_xticks(np.arange(len(col_labels)))
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_xticklabels(col_labels, fontsize=9, fontweight="bold")
    ax.set_yticklabels(row_labels, fontsize=9, fontweight="bold")

    plt.setp(ax.get_xticklabels(), rotation=25, ha="right", rotation_mode="anchor")

    for i in range(len(row_labels)):
        for j in range(len(col_labels)):
            val = data_arr[i, j]
            color = "white" if val > 50 else "black"
            fontweight = "bold" if val > 0 else "normal"
            text_str = f"{val:.0f}%" if val > 0 else "0%"
            ax.text(j, i, text_str, ha="center", va="center", color=color, fontsize=10, fontweight=fontweight)

    cbar = ax.figure.colorbar(im, ax=ax, shrink=0.85)
    cbar.ax.set_ylabel("Vulnerability Exposure Rate (%)", rotation=-90, va="bottom", fontsize=9, fontweight="bold")

    ax.set_title("Figure 2: 9-Layer Policy Pipeline Ablation Matrix (1:1 Layer Attribution Heatmap)", fontsize=11, fontweight="bold", pad=15)
    fig.tight_layout()
    chart2_png = os.path.join(charts_dir, "figure2_ablation_study.png")
    chart2_svg = os.path.join(charts_dir, "figure2_ablation_study.svg")
    plt.savefig(chart2_png)
    plt.savefig(chart2_svg)
    plt.close()
    print(f"[OK] Generated Chart 2 (7x7 Heatmap): {chart2_png}")

    print(f"[SUCCESS] Publication charts successfully generated in: {charts_dir}")


if __name__ == "__main__":
    generate_paper_charts()
