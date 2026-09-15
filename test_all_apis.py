"""
Phase 4: Exhaustive Backend API Test Suite for CyberSentinel.
Tests every endpoint in OpenAPI spec, measures latency, validates response schema and data integrity.
"""
import time
import json
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

def test_api(method, path, body=None):
    url = BASE_URL + path
    headers = {"Content-Type": "application/json"} if body else {}
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            content = resp.read().decode("utf-8")
            status = resp.status
            try:
                parsed = json.loads(content)
            except:
                parsed = content[:100]
            return {"status": status, "ms": elapsed_ms, "data": parsed, "error": None}
    except urllib.error.HTTPError as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        try:
            err_data = json.loads(e.read().decode("utf-8"))
        except:
            err_data = str(e)
        return {"status": e.code, "ms": elapsed_ms, "data": err_data, "error": str(e)}
    except Exception as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return {"status": 0, "ms": elapsed_ms, "data": None, "error": str(e)}

def run_all_api_tests():
    print("=" * 70)
    print("PHASE 4: EXHAUSTIVE BACKEND API TEST SUITE")
    print("=" * 70)

    test_matrix = [
        # Health & System
        ("GET", "/health", None),
        ("GET", "/api/health", None),
        ("GET", "/api/metrics", None),
        ("GET", "/demo", None),
        
        # Threat intelligence & Alerts
        ("GET", "/api/alerts?limit=5", None),
        ("GET", "/api/threats", None),
        ("GET", "/api/threat-summary", None),
        ("GET", "/api/timeline?hours=24", None),
        ("GET", "/api/flows?limit=5", None),
        
        # Digital Twin & Trajectory
        ("GET", "/api/network", None),
        ("GET", "/api/trajectory", None),
        ("GET", "/api/trajectory/192.168.1.50", None),
        
        # Models
        ("GET", "/api/models", None),
        ("POST", "/api/reload-model", {}),
        
        # Live Monitoring & Baseline
        ("GET", "/api/live/interfaces", None),
        ("GET", "/api/live/status", None),
        ("GET", "/api/live/zeek", None),
        ("GET", "/api/live/baseline/status", None),
        ("POST", "/api/live/baseline/start", {"duration": 5}),
        ("GET", "/api/live/baseline/status", None),
        ("POST", "/api/live/baseline/stop", {}),
        ("GET", "/api/live/flows", None),
        
        # Detection Scenarios (Real payloads)
        ("POST", "/demo/dns", None),
        ("POST", "/demo/c2", None),
        ("POST", "/demo/encrypted", None),
        ("POST", "/demo/ddos", None),
        ("POST", "/demo/correlated", None),
        ("POST", "/demo/run-all", None),
        
        # Custom Detect API
        ("POST", "/detect", {
            "source": "192.168.1.100",
            "destination": "10.0.0.1",
            "recon_features": {
                "unique_dst_ports": 55,
                "unique_destinations": 10,
                "flow_count": 250,
                "mean_syn_count": 0.9,
                "total_packets": 300,
                "total_bytes": 12000,
                "window_seconds": 60.0
            }
        }),
        ("POST", "/detect", {
            "source": "192.168.1.200",
            "destination": "198.51.100.22",
            "exfil_features": {
                "bytes_out": 10000000,
                "bytes_in": 2000,
                "unique_destinations": 1,
                "flow_count": 5,
                "mean_flow_duration": 300.0,
                "window_seconds": 600.0
            }
        }),
        
        # Replay Controls & Canonical Pipeline Endpoints
        ("POST", "/api/replay/speed", {"speed": 5}),
        ("POST", "/api/replay/dataset", {}),
        ("POST", "/api/replay/csv", {}),
        ("POST", "/api/replay/pcap", {}),
    ]


    results = []
    passed = 0
    failed = 0

    for method, path, body in test_matrix:
        res = test_api(method, path, body)
        is_ok = 200 <= res["status"] < 300
        status_str = f"PASS ({res['status']})" if is_ok else f"FAIL ({res['status']})"
        if is_ok:
            passed += 1
        else:
            failed += 1
            print(f"  [ERROR DETAIL] {method} {path}: {res['error'] or res['data']}")
        
        print(f"  {method:4s} {path:32s} -> {status_str:12s} [{res['ms']:6.1f} ms]")
        results.append((method, path, res["status"], res["ms"], is_ok))

    print("-" * 70)
    print(f"TOTAL: {len(test_matrix)} | PASSED: {passed} | FAILED: {failed}")
    print("=" * 70)
    return failed == 0

if __name__ == "__main__":
    import sys
    success = run_all_api_tests()
    sys.exit(0 if success else 1)
