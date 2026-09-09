import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np

# Set publication style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['font.family'] = 'sans-serif'

def draw_fig1_architecture():
    fig, ax = plt.subplots(figsize=(10, 6.5), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7.5)
    ax.axis('off')

    plt.title("AuthzGraph System Architecture", fontsize=13, fontweight='bold', pad=15)

    def draw_box(x, y, w, h, title, color="#2B6CB0", bg="#EBF3FA", icon="", fontsize=9):
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08", 
                                     facecolor=bg, edgecolor=color, linewidth=1.4)
        ax.add_patch(rect)
        if icon:
            ax.text(x + w/2, y + h*0.65, f"{icon} {title}", ha='center', va='center', fontsize=fontsize, fontweight='bold', color="#1A202C")
        else:
            ax.text(x + w/2, y + h/2, title, ha='center', va='center', fontsize=fontsize, fontweight='bold', color="#1A202C")

    def draw_arrow(x1, y1, x2, y2, color="#4A5568", label=""):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color=color, lw=1.5, mutation_scale=12))
        if label:
            ax.text((x1+x2)/2, (y1+y2)/2 + 0.12, label, ha='center', va='center', fontsize=7.5, fontweight='bold', color=color)

    # 1. Top Spec Input
    draw_box(2.0, 6.3, 6.0, 0.8, "Target REST API (OpenAPI/Swagger Specification)", "#3182CE", "#EBF8FF", "[SPEC]")

    # 2. Spec Parser & Session Manager
    draw_box(0.5, 5.0, 4.2, 0.8, "Spec Parser & Object Graph Builder", "#2F855A", "#F0FFF4", "[PARSER]")
    draw_box(5.3, 5.0, 4.2, 0.8, "Multi-Identity Session Manager", "#2F855A", "#F0FFF4", "[SESSIONS]")

    draw_arrow(4.0, 6.3, 2.6, 5.8)
    draw_arrow(6.0, 6.3, 7.4, 5.8)

    # 3. Central Authorization Engine Layered Policy Pipeline
    container = patches.FancyBboxPatch((0.4, 2.7), 9.2, 1.8, boxstyle="round,pad=0.12",
                                       facecolor="#F7FAFC", edgecolor="#D69E2E", linewidth=1.6)
    ax.add_patch(container)
    ax.text(5.0, 4.25, "Central Authorization Engine — Layered Policy Pipeline", ha='center', fontsize=10, fontweight='bold', color="#B7791F")

    # 7 Internal Layers
    layers = [
        ("AuthN", "#3182CE", "#EBF8FF"),
        ("BFLA", "#E53E3E", "#FFF5F5"),
        ("RBAC", "#DD6B20", "#FEEBC8"),
        ("BOPLA", "#D69E2E", "#FEFCBF"),
        ("BOLA", "#38A169", "#F0FFF4"),
        ("ABAC", "#319795", "#E6FFFA"),
        ("MAC", "#805AD5", "#FAF5FF")
    ]

    for i, (name, border, bg) in enumerate(layers):
        x = 0.65 + i * 1.25
        draw_box(x, 3.0, 1.1, 0.9, name, border, bg, fontsize=8.5)
        if i < len(layers) - 1:
            draw_arrow(x + 1.1, 3.45, x + 1.25, 3.45, color="#A0AEC0")

    draw_arrow(2.6, 5.0, 2.6, 4.5)
    draw_arrow(7.4, 5.0, 7.4, 4.5)

    # 4. Decision Node
    draw_box(2.2, 1.5, 5.6, 0.7, "Decision: ALLOW (200) / DENY (403) + Audit Log Entry", "#38A169", "#F0FFF4", "[DECISION]")
    draw_arrow(5.0, 2.7, 5.0, 2.2)

    # 5. Downstream Harnesses
    draw_box(0.5, 0.3, 4.2, 0.8, "Benchmark & Ablation Harness", "#805AD5", "#FAF5FF", "[BENCHMARK]")
    draw_box(5.3, 0.3, 4.2, 0.8, "Cross-App Validation (RideX, vAPI)", "#805AD5", "#FAF5FF", "[CROSS-APP]")

    draw_arrow(3.5, 1.5, 2.6, 1.1)
    draw_arrow(6.5, 1.5, 7.4, 1.1)

    plt.tight_layout()
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/fig1_architecture.png", dpi=300, bbox_inches='tight')
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/intro.png", dpi=300, bbox_inches='tight')
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/architecture_diagram.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated fig1_architecture.png")

def draw_fig2_pipeline():
    fig, ax = plt.subplots(figsize=(10, 3.5), dpi=300)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3.5)
    ax.axis('off')

    plt.title("Vulnerability Detection Pipeline Workflow", fontsize=12, fontweight='bold', pad=12)

    nodes = [
        ("OpenAPI\nSpec Input", "[SPEC]", "#3182CE", "#EBF8FF"),
        ("Object Graph\n& Identity Map", "[GRAPH]", "#2F855A", "#F0FFF4"),
        ("Attack Vector\nGeneration", "[VECTORS]", "#D69E2E", "#FEFCBF"),
        ("Live HTTP\nReplay", "[REPLAY]", "#DD6B20", "#FEEBC8"),
        ("Response\nClassifier", "[CLASSIFY]", "#805AD5", "#FAF5FF"),
        ("Structured\nReport", "[REPORT]", "#C53030", "#FFF5F5")
    ]

    for i, (title, icon, border, bg) in enumerate(nodes):
        x = 0.35 + i * 1.55
        y = 1.0
        w = 1.35
        h = 1.4

        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08", 
                                     facecolor=bg, edgecolor=border, linewidth=1.4)
        ax.add_patch(rect)
        ax.text(x + w/2, y + h*0.72, icon, ha='center', va='center', fontsize=9, fontweight='bold', color=border)
        ax.text(x + w/2, y + h*0.35, title, ha='center', va='center', fontsize=8, fontweight='bold', color="#1A202C")

        if i < len(nodes) - 1:
            ax.annotate('', xy=(x + w + 0.18, y + h/2), xytext=(x + w + 0.02, y + h/2),
                        arrowprops=dict(arrowstyle="->", color="#4A5568", lw=1.5, mutation_scale=12))

    plt.tight_layout()
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/fig2_pipeline.png", dpi=300, bbox_inches='tight')
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/algorithm2.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated fig2_pipeline.png")

def draw_fig3_ablation_matrix():
    fig, ax = plt.subplots(figsize=(7, 6), dpi=300)

    # 7x7 Diagonal Isolation Matrix
    labels = ['RBAC', 'BFLA', 'BOPLA', 'BOLA', 'ABAC', 'MAC-Read', 'MAC-Write']
    data = np.zeros((7, 7))
    np.fill_diagonal(data, 100.0)

    im = ax.imshow(data, cmap='Reds', vmin=0, vmax=100)
    cbar = ax.figure.colorbar(im, ax=ax, shrink=0.8)
    cbar.ax.set_ylabel("Exposure Rate (%)", rotation=-90, va="bottom", fontsize=8.5, fontweight='bold')

    ax.set_xticks(np.arange(len(labels)))
    ax.set_yticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, fontsize=8.5, fontweight='bold')
    ax.set_yticklabels(labels, fontsize=8.5, fontweight='bold')

    plt.xticks(rotation=45, ha='right')

    # Annotate cell values
    for i in range(len(labels)):
        for j in range(len(labels)):
            val = int(data[i, j])
            color = "white" if val > 50 else "black"
            ax.text(j, i, f"{val}%", ha="center", va="center", color=color, fontsize=9, fontweight="bold")

    ax.set_title("Layer-Ablation Isolation Matrix (N=10 trials/config)", fontsize=11, fontweight='bold', pad=12)
    ax.set_xlabel("Exposure Rate Measured On →", fontsize=9.5, fontweight='bold')
    ax.set_ylabel("↓ Layer Disabled", fontsize=9.5, fontweight='bold')

    plt.tight_layout()
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/fig3_ablation_matrix.png", dpi=300, bbox_inches='tight')
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/algorithm.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated fig3_ablation_matrix.png")

def draw_fig4_attack_success_rate():
    fig, ax = plt.subplots(figsize=(8.5, 4.5), dpi=300)

    vectors = [
        'BOLA\nSingle',
        'BOLA\nEnum.',
        'BOPLA\nMass Assign.',
        'BFLA\nAdmin Probe',
        'BFLA\nVerb Switch',
        'ABAC\nCross-Region',
        'MAC\nRead-Up',
        'RBAC\nPerm. Denied'
    ]

    vulnerable_er = [100.0] * 8
    secure_er = [0.0] * 8

    x = np.arange(len(vectors))
    width = 0.38

    rects1 = ax.bar(x - width/2, vulnerable_er, width, label='VULNERABLE mode', color='#C53030', edgecolor='#9B2C2C')
    rects2 = ax.bar(x + width/2, secure_er, width, label='SECURE mode', color='#3182CE', edgecolor='#2B6CB0')

    ax.set_ylabel('Exposure Rate (%)', fontsize=10, fontweight='bold')
    ax.set_title('Attack Success Rate: VULNERABLE vs. SECURE Mode (N=15 trials/vector)', fontsize=11, fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(vectors, fontsize=8.5, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.grid(True, linestyle=':', alpha=0.6, axis='y')
    ax.legend(frameon=True, facecolor='white', edgecolor='#CBD5E0', fontsize=9.5, loc='upper right')

    for rect in rects1:
        height = rect.get_height()
        ax.annotate('100%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, fontweight='bold', color='#9B2C2C')

    for rect in rects2:
        height = rect.get_height()
        ax.annotate('0%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=8, fontweight='bold', color='#2B6CB0')

    plt.tight_layout()
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/fig4_attack_success_rate.png", dpi=300, bbox_inches='tight')
    plt.savefig("C:/Users/ayila/OneDrive/Desktop/authgraph/Docs/graph.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("Generated fig4_attack_success_rate.png")

if __name__ == "__main__":
    draw_fig1_architecture()
    draw_fig2_pipeline()
    draw_fig3_ablation_matrix()
    draw_fig4_attack_success_rate()
    print("All AuthzGraph diagrams rendered successfully!")
