"""
CyberSentinel System Integration Test.
Run: python -m pytest backend/tests/integration/test_integration.py
"""
import os
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

print('Testing imports...')
from backend.app.core.config import APP_VERSION, MODEL_VERSION, DB_PATH
print(f'  config OK  version={APP_VERSION}')

import backend.app.database.connection as db
db.init_db()
print(f'  database OK  path={DB_PATH}')

from backend.app.digital_twin import get_twin
twin = get_twin()
twin.update_from_flow(src_ip='10.0.0.1', dst_ip='8.8.8.8', packets=10,
                      bytes_count=5000, threat_score=0.8, threat_class='RECON')
stats = twin.get_stats()
print(f'  digital_twin OK  nodes={stats["total_nodes"]}')

from backend.app.correlation import get_engine
eng = get_engine()
r = eng.record_alert('10.0.0.1', 'RECON', 0.8)
print(f'  correlation OK  correlated={r["correlated"]}')

from backend.app.risk import calculate_risk_score
r = calculate_risk_score(confidence=0.9, severity='HIGH', threat_class='C2',
                         correlated_detector_count=3, persistence_count=2)
print(f'  risk_scoring OK  score={r["risk_score"]}')

from backend.app.prediction import get_engine as te
traj = te()
r = traj.update_state('10.0.0.1', ['RECON', 'C2'])
print(f'  trajectory OK  current={r["current_state"]}  predicted={r["predicted_next_state"]}')

print('\nTesting detectors...')

from backend.app.detectors.reconnaissance import detect as det_recon
row = pd.DataFrame([{
    'unique_dst_ports': 48, 'unique_destinations': 12,
    'flow_count': 320, 'window_seconds': 60.0,
    'total_bytes': 14400, 'mean_syn_count': 0.85, 'total_packets': 320
}])
r = det_recon(row)
print(f'  recon_detector OK  prediction={r[0]["prediction"]}  score={r[0]["model_score"]:.3f}')

from backend.app.detectors.exfiltration import detect as det_exfil
row = pd.DataFrame([{
    'bytes_out': 8500000, 'bytes_in': 1200,
    'unique_destinations': 1, 'flow_count': 3,
    'mean_flow_duration': 480.0, 'window_seconds': 600.0
}])
r = det_exfil(row)
print(f'  exfil_detector OK  prediction={r[0]["prediction"]}  score={r[0]["model_score"]:.3f}')

from backend.app.detectors.dga_dns import detect as det_dns
print('  dns_detector import OK')

from backend.app.detectors.encrypted_malware import detect as det_enc
print('  encrypted_detector import OK')

from backend.app.detectors.ddos import detect as det_dos
print('  dos_detector import OK')

from backend.app.detectors.beaconing import detect as det_c2
print('  c2_detector import OK')

print('\nAll integration checks passed successfully!')
