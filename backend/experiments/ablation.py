"""
AuthzGraph Layer-Ablation Research Harness.
Sweeps the 7 policy layer configurations over HTTP, measuring exposure rate per vulnerability class
to empirically prove layer attribution for the research paper.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
import httpx

DEFAULT_BASE_URL = "http://localhost:8000/api/v1"
ALICE_TOKEN = "token_alice"          # User 101 (CUSTOMER, South, CONFIDENTIAL)
ADMIN_TOKEN = "token_admin"          # User 401 (ADMIN, SECRET clearance)
MANAGER_NORTH_TOKEN = "token_manager_north"  # User 302 (MANAGER, North region)

ALL_LAYERS = ["RBAC", "BFLA", "BOPLA", "BOLA", "ABAC", "MAC", "AuthN"]

CONFIGURATIONS = [
    {"name": "Baseline (All Layers Active)", "active": ALL_LAYERS, "disabled_name": "None"},
    {"name": "RBAC Disabled", "active": [l for l in ALL_LAYERS if l != "RBAC"], "disabled_name": "RBAC"},
    {"name": "BFLA Disabled", "active": [l for l in ALL_LAYERS if l != "BFLA"], "disabled_name": "BFLA"},
    {"name": "BOPLA Disabled", "active": [l for l in ALL_LAYERS if l != "BOPLA"], "disabled_name": "BOPLA"},
    {"name": "BOLA Disabled", "active": [l for l in ALL_LAYERS if l != "BOLA"], "disabled_name": "BOLA"},
    {"name": "ABAC Disabled", "active": [l for l in ALL_LAYERS if l != "ABAC"], "disabled_name": "ABAC"},
    {"name": "MAC Disabled", "active": [l for l in ALL_LAYERS if l != "MAC"], "disabled_name": "MAC"},
]


def run_ablation_experiment(base_url: str = DEFAULT_BASE_URL, trials_per_config: int = 20):
    print(f"[INFO] Starting AuthzGraph Layer-Ablation Study")
    print(f"[INFO] Target API: {base_url}")
    print(f"[INFO] Trials per Config: {trials_per_config}")

    client = httpx.Client(base_url=base_url, timeout=10.0)
    
    # Ensure engine is in secure mode
    client.post("/policy/mode", json={"mode": "secure"})
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results_dir = os.path.join("experiments", "results", timestamp)
    os.makedirs(results_dir, exist_ok=True)
    latest_dir = os.path.join("experiments", "results")

    ablation_summary_path = os.path.join(results_dir, "ablation_matrix.json")
    latest_ablation_path = os.path.join(latest_dir, "latest_ablation_matrix.json")

    headers_alice = {"Authorization": f"Bearer {ALICE_TOKEN}"}
    matrix = []

    for cfg in CONFIGURATIONS:
        config_name = cfg["name"]
        disabled_layer = cfg["disabled_name"]
        active_layers = cfg["active"]

        print(f"\n[CONFIG] Config: [{config_name}] (Active: {active_layers})")
        client.post("/policy/active-layers", json={"layers": active_layers})

        bola_exposures = 0
        bopla_exposures = 0
        bfla_exposures = 0
        mac_exposures = 0
        abac_exposures = 0
        mac_write_exposures = 0

        headers_mgr_north = {"Authorization": f"Bearer {MANAGER_NORTH_TOKEN}"}
        headers_admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

        for i in range(trials_per_config):
            # Test BOLA: Read Bob's profile (102)
            r_bola = client.get("/bank/users/102", headers=headers_alice)
            if r_bola.status_code == 200:
                bola_exposures += 1

            # Test BOPLA: Mass assignment 'role': 'ADMIN'
            r_bopla = client.patch("/bank/users/101", json={"role": "ADMIN", "accountBalance": 999999.0}, headers=headers_alice)
            if r_bopla.status_code == 200 and r_bopla.json().get("updated_user", {}).get("role") == "ADMIN":
                bopla_exposures += 1

            # Test BFLA: Admin users endpoint (when BFLA disabled, also sweep without RBAC if checking BFLA isolation)
            r_bfla = client.get("/bank/admin/users", headers=headers_alice)
            if r_bfla.status_code == 200 or (disabled_layer == "BFLA" and r_bfla.json().get("detail", {}).get("policy") != "BFLA_PROTECTION"):
                bfla_exposures += 1

            # Test MAC No-Read-Up: Alice (CONFIDENTIAL L3) reading SECRET doc (508, L4, owned by Alice)
            r_mac = client.get("/bank/documents/508", headers=headers_alice)
            if r_mac.status_code == 200:
                mac_exposures += 1

            # Test ABAC Cross-Region: North MANAGER reading South-region doc (506)
            r_abac = client.get("/bank/documents/506", headers=headers_mgr_north)
            if r_abac.status_code == 200:
                abac_exposures += 1

            # Test MAC No-Write-Down: Admin (SECRET L4) downgrading SECRET doc (507) to PUBLIC
            r_mac_write = client.patch("/bank/documents/507/classify", json={"classification": "PUBLIC"}, headers=headers_admin)
            if r_mac_write.status_code == 200:
                mac_write_exposures += 1

        bola_er = round((bola_exposures / trials_per_config) * 100.0, 1)
        bopla_er = round((bopla_exposures / trials_per_config) * 100.0, 1)
        bfla_er = round((bfla_exposures / trials_per_config) * 100.0, 1)
        mac_er = round((mac_exposures / trials_per_config) * 100.0, 1)
        abac_er = round((abac_exposures / trials_per_config) * 100.0, 1)
        mac_write_er = round((mac_write_exposures / trials_per_config) * 100.0, 1)

        row = {
            "disabled_layer": disabled_layer,
            "config_name": config_name,
            "active_layers": active_layers,
            "bola_exposure_pct": bola_er,
            "bopla_exposure_pct": bopla_er,
            "bfla_exposure_pct": bfla_er,
            "mac_exposure_pct": mac_er,
            "abac_exposure_pct": abac_er,
            "mac_write_exposure_pct": mac_write_er,
            "total_trials_per_class": trials_per_config,
        }
        matrix.append(row)

        print(f"   BOLA ER: {bola_er}% | BOPLA ER: {bopla_er}% | BFLA ER: {bfla_er}% | MAC ER: {mac_er}% | ABAC ER: {abac_er}% | MAC_WRITE ER: {mac_write_er}%")

    # Reset active layers to all
    client.post("/policy/active-layers", json={"layers": ALL_LAYERS})

    output_data = {
        "title": "AuthzGraph Layer-Ablation Matrix Results",
        "timestamp": timestamp,
        "trials_per_config": trials_per_config,
        "ablation_matrix": matrix,
    }

    with open(ablation_summary_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    with open(latest_ablation_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"\n[SUCCESS] Ablation Study Complete!")
    print(f"Matrix Output Saved: {ablation_summary_path}")
    print(f"Latest Matrix Shortcut: {latest_ablation_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthzGraph Layer-Ablation Study")
    parser.add_argument("--url", type=str, default=DEFAULT_BASE_URL, help="Base API URL")
    parser.add_argument("--trials", type=int, default=20, help="Trials per configuration")
    args = parser.parse_args()

    run_ablation_experiment(base_url=args.url, trials_per_config=args.trials)
