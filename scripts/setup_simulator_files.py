import sys
sys.path.insert(0, ".")
import json
from backend.app.services.replay_service import VERIFIED_SCENARIOS

# Write scenarios
for name, data in VERIFIED_SCENARIOS.items():
    with open(f'simulator/scenarios/{name}.json', 'w') as f:
        json.dump(data, f, indent=2)

# Also normal scenario
with open('simulator/scenarios/normal.json', 'w') as f:
    json.dump({
        "source": "192.168.1.55",
        "destination": "142.250.190.46",
        "domain": "www.google.com",
        "time_window": "2026-09-13T12:00:00",
        "recon_features": {"flow_count": 1, "unique_dst_ports": 1, "total_bytes": 1200}
    }, f, indent=2)

# Simulator replay runner
with open('simulator/replay.py', 'w') as f:
    f.write('''"""
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
''')

with open('simulator/README.md', 'w') as f:
    f.write('''# CyberSentinel Attack Simulator & Replayer
Provides repeatable, deterministic replay scenarios for evaluation and offline demonstrations.
''')

print('Simulator subsystem initialized successfully.')
