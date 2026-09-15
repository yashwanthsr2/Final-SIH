"""
Benchmark & False Positive Analysis for Normal Browsing Traffic.

Exercises realistic normal user and system activity:
1. Google Search
2. YouTube Video & Page Loading
3. Several Major HTTPS Websites (Wikipedia, GitHub, Cloudflare, StackOverflow, Microsoft)
4. DNS Resolutions (30+ legitimate domains)
5. Parallel CDN Edge Connections (Cloudflare, Akamai, Google, Fastly)
6. Browser Background Connections (Keep-Alives, WebSockets, persistent TLS sessions)

Measures:
- Initial vs Final Alert Count
- Per-detector firing analysis
- Identified False Positive root causes
- Telemetry throughput and flow metrics
"""
import concurrent.futures
import json
import socket
import time
import urllib.request
from typing import Any, Dict, List, Tuple

SERVER_URL = "http://127.0.0.1:8000"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}

DOMAINS_TO_RESOLVE = [
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "i.ytimg.com", "yt3.ggpht.com", "fonts.googleapis.com", "ssl.gstatic.com",
    "wikipedia.org", "en.wikipedia.org", "upload.wikimedia.org",
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "cloudflare.com", "1.1.1.1", "cdnjs.cloudflare.com",
    "stackoverflow.com", "microsoft.com", "www.microsoft.com",
    "azure.com", "aws.amazon.com", "apple.com", "reddit.com",
    "netflix.com", "linkedin.com", "bing.com", "yahoo.com"
]

HTTPS_TARGETS = [
    ("Google Search", "https://www.google.com/search?q=cyber+threat+detection+unidirectional+traffic"),
    ("Google Assets", "https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap"),
    ("YouTube Home", "https://www.youtube.com"),
    ("YouTube Search", "https://www.youtube.com/results?search_query=network+security+tutorial"),
    ("Wikipedia Deep Learning", "https://en.wikipedia.org/wiki/Deep_learning"),
    ("Wikipedia Cyber Security", "https://en.wikipedia.org/wiki/Computer_security"),
    ("GitHub API Zen", "https://api.github.com/zen"),
    ("Cloudflare 1.1.1.1", "https://1.1.1.1"),
    ("StackOverflow", "https://stackoverflow.com"),
    ("Microsoft Home", "https://www.microsoft.com"),
]

CDN_TARGETS = [
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css",
    "https://fonts.gstatic.com/s/inter/v13/UcC73FwrK3iLTeHuS_fvQtMwCp50KnMa1ZL7W0Q5nw.woff2",
    "https://upload.wikimedia.org/wikipedia/commons/thumb/1/10/Wikipedia-logo-v2-en.svg/1200px-Wikipedia-logo-v2-en.svg.png",
    "https://github.githubassets.com/favicons/favicon.png",
]

def get_server_alerts() -> List[Dict[str, Any]]:
    try:
        with urllib.request.urlopen(f"{SERVER_URL}/api/alerts?limit=200", timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data.get("alerts", [])
    except Exception:
        return []

def get_live_status() -> Dict[str, Any]:
    try:
        with urllib.request.urlopen(f"{SERVER_URL}/api/live/status", timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}

def fetch_url(target: Tuple[str, str]) -> Dict[str, Any]:
    name, url = target
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=12) as resp:
            content = resp.read()
            return {
                "name": name,
                "url": url,
                "status": resp.getcode(),
                "bytes": len(content),
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "success": True,
            }
    except Exception as exc:
        return {
            "name": name,
            "url": url,
            "status": 0,
            "bytes": 0,
            "latency_ms": round((time.time() - t0) * 1000, 1),
            "success": False,
            "error": str(exc),
        }

def run_benchmark(label: str = "BENCHMARK") -> Dict[str, Any]:
    print("\n" + "=" * 70)
    print(f"RUNNING FALSE-POSITIVE BENCHMARK: {label}")
    print("=" * 70)

    # 1. Capture baseline state
    initial_alerts = get_server_alerts()
    initial_alert_ids = {a.get("id") or a.get("alert_id") for a in initial_alerts}
    status_start = get_live_status()
    t_start = time.time()

    print(f"[*] Initial Active Server Alerts: {len(initial_alerts)}")
    print(f"[*] Initial Packets Observed   : {status_start.get('packets_seen', 0):,}")
    print(f"[*] Initial Bytes Observed     : {status_start.get('bytes_seen', 0):,}")

    # 2. Activity A: DNS Resolutions
    print("\n[A] Executing Realistic DNS Lookups (30+ major domains)...")
    resolved_ips = []
    t_dns_start = time.time()
    for domain in DOMAINS_TO_RESOLVE:
        try:
            addrinfo = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            ips = list({res[4][0] for res in addrinfo})
            resolved_ips.extend(ips)
        except Exception:
            pass
    print(f"    Resolved {len(DOMAINS_TO_RESOLVE)} domains to {len(resolved_ips)} distinct IPs in {round((time.time() - t_dns_start)*1000, 1)} ms.")

    # 3. Activity B: Sequential & Parallel HTTPS Browsing
    print("\n[B] Executing HTTPS Web Browsing (Google, YouTube, Wikipedia, etc.)...")
    results_https = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(fetch_url, target) for target in HTTPS_TARGETS]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            results_https.append(res)
            status_str = f"HTTP {res['status']}" if res['success'] else "FAILED"
            print(f"    - {res['name']:25} | {status_str:8} | {res['bytes']:,} B | {res['latency_ms']} ms")

    # 4. Activity C: CDN Edge Multiplexing
    print("\n[C] Executing Parallel CDN Media & Script Downloads...")
    results_cdn = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(fetch_url, (f"CDN-{i}", url)) for i, url in enumerate(CDN_TARGETS)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            results_cdn.append(res)
            print(f"    - {res['name']:25} | {res['bytes']:,} B | {res['latency_ms']} ms")

    # 5. Activity D: Persistent Browser Connections & Keep-Alives
    print("\n[D] Executing Browser Background Keep-Alives & Polling...")
    bg_bytes = 0
    for i in range(4):
        try:
            req = urllib.request.Request("https://www.google.com/generate_204", headers=HEADERS)
            with urllib.request.urlopen(req, timeout=5) as resp:
                bg_bytes += len(resp.read())
            time.sleep(0.5)
        except Exception:
            pass
    print("    Completed 4 keep-alive 204 pings.")

    # 6. Allow sliding window to ingest and finalize
    print("\n[*] Waiting for sliding live window to ingest telemetry and run inference...")
    time.sleep(5.0)

    # 7. Measure after
    status_end = get_live_status()
    all_current_alerts = get_server_alerts()
    new_alerts = [
        a for a in all_current_alerts 
        if (a.get("id") or a.get("alert_id")) not in initial_alert_ids
    ]

    total_web_bytes = sum(r["bytes"] for r in results_https) + sum(r["bytes"] for r in results_cdn) + bg_bytes
    delta_pkts = status_end.get("packets_seen", 0) - status_start.get("packets_seen", 0)
    delta_bytes = status_end.get("bytes_seen", 0) - status_start.get("bytes_seen", 0)
    delta_flows = status_end.get("flows_seen", 0) - status_start.get("flows_seen", 0)

    print("\n" + "-" * 70)
    print("TELEMETRY OBSERVED DURING TEST:")
    print(f"  - Web Payload Downloaded: {total_web_bytes:,} bytes ({total_web_bytes / (1024*1024):.2f} MB)")
    print(f"  - Total Packets Ingested : +{delta_pkts:,}")
    print(f"  - Total Bytes Ingested   : +{delta_bytes:,} bytes ({delta_bytes / (1024*1024):.2f} MB)")
    print(f"  - Flows Generated        : +{delta_flows:,}")
    print("-" * 70)

    # 8. False Positive Breakdown
    alerts_by_threat: Dict[str, List[Dict[str, Any]]] = {}
    for a in new_alerts:
        t_class = a.get("primary_threat") or a.get("threat_class") or "UNKNOWN"
        alerts_by_threat.setdefault(t_class, []).append(a)

    print(f"NEW ALERTS GENERATED: {len(new_alerts)}")
    for t_class, al_list in alerts_by_threat.items():
        print(f"  * Threat Category [{t_class}]: {len(al_list)} alert(s)")
        for a in al_list[:2]:
            print(f"    - Severity: {a.get('severity')}, Risk: {a.get('risk_score')}, Conf: {a.get('confidence')}")
            for ev in a.get("evidence", [])[:3]:
                print(f"      Signal: {ev.get('feature')} = {ev.get('value')} ({ev.get('human_label')})")

    summary = {
        "label": label,
        "duration_sec": round(time.time() - t_start, 2),
        "total_web_bytes": total_web_bytes,
        "delta_pkts": delta_pkts,
        "delta_bytes": delta_bytes,
        "delta_flows": delta_flows,
        "new_alert_count": len(new_alerts),
        "alerts_by_threat": {k: len(v) for k, v in alerts_by_threat.items()},
        "new_alerts": new_alerts,
    }
    return summary

if __name__ == "__main__":
    res = run_benchmark("INITIAL_RUN")
    with open("scripts/benchmark_initial_result.json", "w") as f:
        json.dump(res, f, indent=2)
