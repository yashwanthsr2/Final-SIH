import urllib.request, json, sys
sys.stdout.reconfigure(encoding='utf-8')

endpoints = [
    ('/', 'text/html'),
    ('/api/health', 'application/json'),
    ('/api/flows?limit=5', 'application/json'),
    ('/api/alerts?limit=5', 'application/json'),
    ('/api/network', 'application/json'),
    ('/api/models', 'application/json'),
    ('/api/trajectory', 'application/json'),
    ('/api/live/interfaces', 'application/json'),
    ('/api/live/status', 'application/json')
]

print("Testing CyberSentinel backend endpoints:")
for ep, ctype in endpoints:
    url = f"http://127.0.0.1:8000{ep}"
    try:
        req = urllib.request.urlopen(url, timeout=3)
        status = req.status
        content = req.read()
        print(f"  {ep} -> HTTP {status} ({len(content)} bytes)")
    except Exception as e:
        print(f"  {ep} -> FAILED ({e})")
