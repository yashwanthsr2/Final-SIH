"""
CyberSentinel Offline Attack Simulator & Scenario Replayer.
"""
import sys
import json
import time
import requests
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent / "scenarios"

def replay_scenario(scenario_name: str, backend_url: str = "http://127.0.0.1:8000"):
    p = SCENARIOS_DIR / f"{scenario_name}.json"
    if not p.exists():
        print(f"Scenario not found: {scenario_name}")
        return
    with open(p) as f:
        payload = json.load(f)
    resp = requests.post(f"{backend_url}/detect", json=payload)
    print(f"[{scenario_name}] Status: {resp.status_code} Response: {resp.json()}")

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "dns"
    replay_scenario(name)
