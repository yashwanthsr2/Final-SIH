import urllib.request
import json

req = urllib.request.urlopen('http://127.0.0.1:8000/api/trajectory')
data = json.loads(req.read().decode())
print('Total Trajectories Tracked:', data.get('count'))
print('Tracked Sources:', [t['source'] for t in data.get('trajectories', [])])

# Query host 192.168.1.100
req_host = urllib.request.urlopen('http://127.0.0.1:8000/api/trajectory/192.168.1.100')
h_data = json.loads(req_host.read().decode())
print('\nTrajectory Data for 192.168.1.100 (served directly to Dashboard):')
print('  CURRENT STATE       :', h_data.get('current_state'))
print('  PREDICTED NEXT STATE:', h_data.get('predicted_next_state'))
print('  CONFIDENCE          :', h_data.get('prediction_confidence'))
print('  REASONING           :', h_data.get('prediction_reasoning'))
print('  HISTORY STAGES      :', [f"{h['from']} -> {h['to']}" for h in h_data.get('state_history', [])])
print('  PROBABILITY DISTS   :', h_data.get('all_possible_next_states'))
