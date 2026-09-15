"""Run CyberSentinel end-to-end validation."""
import urllib.request, json, time

time.sleep(2)

# Health check
r = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)
d = json.loads(r.read())
print('Health:', d['status'], 'v' + d['version'])
print('Detectors:', d['detectors'])

# Run all demo scenarios
print('\nRunning full demo...')
req = urllib.request.Request('http://127.0.0.1:8000/demo/run-all', method='POST',
    headers={'Content-Type': 'application/json'})
r = urllib.request.urlopen(req, timeout=30)
d = json.loads(r.read())
print('Scenarios run:', d['scenarios_run'])
print('Alert count:', d['alert_count'])
print()

for name, res in d['results'].items():
    pred = res.get('prediction', '?')
    threat = res.get('threat_class') or res.get('primary_threat') or 'NONE'
    risk = res.get('risk_score', '?')
    state = res.get('current_state', '?')
    nxt = res.get('predicted_next_state', '?')
    conf = res.get('confidence', res.get('score', 0))
    corr = 'CORR' if res.get('correlated') else ''
    print(f'  {name:12}: {pred:8} | {str(threat):22} | risk={str(risk):3} | conf={float(conf):.2f} | {state} -> {nxt} {corr}')

# Check network graph
r = urllib.request.urlopen('http://127.0.0.1:8000/api/network', timeout=5)
g = json.loads(r.read())
print(f'\nNetwork graph: {g["node_count"]} nodes, {g["edge_count"]} edges')

# Check trajectory
r = urllib.request.urlopen('http://127.0.0.1:8000/api/trajectory', timeout=5)
t = json.loads(r.read())
print(f'Trajectories tracked: {len(t["trajectories"])}')

# Check alerts
r = urllib.request.urlopen('http://127.0.0.1:8000/api/alerts?limit=3', timeout=5)
d = json.loads(r.read())
total = d['count']
print(f'Alerts in DB: {total}')

# Check threat summary
r = urllib.request.urlopen('http://127.0.0.1:8000/api/threat-summary', timeout=5)
s = json.loads(r.read())
print('Threat summary:', json.dumps(s.get('by_threat_class', [])[:5], indent=2))

print('\n=== END-TO-END VALIDATION COMPLETE ===')
