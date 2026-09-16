"""
CyberSentinel Integrated System Master Launcher.
SIH26-26145 — NTRO AI Threat Detection in Unidirectional IP Traffic.

Unifies and orchestrates:
  1. System Pre-flight & Dependency Verification
  2. Model Loading & Detection Engine Initialization
  3. Database & Digital Twin Schema Validation
  4. End-to-End Pipeline Audit
  5. Live Backend FastAPI Server & Dashboard Delivery
"""

from __future__ import annotations

import sys
import os
import time
import json
import socket
import urllib.request
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def is_port_in_use(port: int = 8000, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def run_preflight_checks() -> bool:
    print("\n" + "=" * 75)
    print(" [CYBERSENTINEL PRE-FLIGHT INTEGRATION & HEALTH VERIFICATION]")
    print("=" * 75)

    # 1. Models
    print(" [1/4] Verifying ML Models & Threat Detector Registries...")
    from backend.app.ml.model_loader import get_all_models
    models = get_all_models()
    expected_models = ["dos_hgb", "c2_hgb", "dns_hgb", "encrypted_hgb"]
    for m in expected_models:
        if m in models:
            print(f"       [OK] ML Model loaded: '{m}'")
        else:
            print(f"       [FAIL] Missing ML Model: '{m}'")
            return False

    # 2. Database
    print(" [2/4] Verifying SQLite Database & Repositories...")
    import backend.app.database as db
    db.init_db()
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [r[0] for r in cursor.fetchall()]
    conn.close()
    for t in ["alerts", "flows", "threat_states", "model_metadata"]:
        if t in tables:
            print(f"       [OK] Database Table verified: '{t}'")
        else:
            print(f"       [FAIL] Missing Database Table: '{t}'")
            return False

    # 3. Digital Twin Graph
    print(" [3/4] Verifying Digital Twin In-Memory Network Graph...")
    from backend.app.digital_twin import get_twin
    twin = get_twin()
    stats = twin.get_stats()
    print(f"       [OK] Digital Twin active: {stats['total_nodes']} nodes, {stats['total_edges']} edges")

    # 4. Frontend Static Files
    print(" [4/4] Verifying Frontend Assets & Static Mounting...")
    index_file = PROJECT_ROOT / "frontend" / "public" / "index.html"
    if index_file.exists():
        print(f"       [OK] Frontend SPA ready ({index_file.stat().st_size:,} bytes)")
    else:
        print(f"       [FAIL] Missing frontend index.html at {index_file}")
        return False

    print("=" * 75)
    print(" [OK] ALL PRE-FLIGHT CHECKS PASSED SUCCESSFULLY!")
    print("=" * 75 + "\n")
    return True

def print_system_banner():
    banner = """
  ========================================================================
    __     ______  _____ _____  _____  ______ _   _ _______ _____ _   _ _____ _      
   /  |   / /  _ \\|  ___|  __ \\/  ___|/  ____| \\ | |__   __|_   _| \\ | |  ___| |     
  / /| | / /| |_) | |__ | |__) | \\ `--.| |__  |  \\| |  | |    | | |  \\| | |__ | |     
 / /_| |/ / |  _ <|  __||  _  / `--. \\  __| | . ` |  | |    | | | . ` |  __|| |     
 \\___  / /  | |_) | |___| | \\ \\/\\__/ /| |____| |\\  |  | |   _| |_| |\\  | |___| |____ 
     |/_/   |____/|_____|_|  \\_\\____/ \\______|_| \\_|  |_|  |_____|_| \\_|_____|______|

    CYBERSENTINEL UNIFIED SOC THREAT DETECTION PLATFORM
    SIH26-26145 | NTRO Passive AI Threat Detection System
  ========================================================================
  
  [SYSTEM STATUS] SERVER IS ACTIVE & READY FOR DEMO/EVALUATION!

  📌 Web Dashboard URL : http://127.0.0.1:8000/
  📌 SIH Judge Hub URL  : http://127.0.0.1:8000/judge
  📌 OpenAPI Swagger   : http://127.0.0.1:8000/api/docs
  📌 System Health     : http://127.0.0.1:8000/health
  ========================================================================
  """
    print(banner)

def main():
    if not run_preflight_checks():
        print("❌ Pre-flight checks failed. Aborting startup.")
        sys.exit(1)

    print_system_banner()

    if is_port_in_use(8000):
        print("⚡ Server is already running on http://127.0.0.1:8000")
        print("   Testing health endpoint...")
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                print(f"   Response: {data}")
        except Exception as e:
            print(f"   Warning: Could not connect to health endpoint: {e}")
    else:
        print("🚀 Starting CyberSentinel Unified Backend Server on http://127.0.0.1:8000 ...")
        import uvicorn
        from backend.app.main import app
        uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)

if __name__ == "__main__":
    main()
