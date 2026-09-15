import shutil, os

# Copy existing test files to target folders
shutil.copy2('test_integration.py', 'tests/integration/test_integration.py')
shutil.copy2('test_integration.py', 'backend/tests/integration/test_integration.py')

shutil.copy2('test_six_detectors.py', 'tests/integration/test_six_detectors.py')
shutil.copy2('test_live_pipeline.py', 'tests/integration/test_live_pipeline.py')

shutil.copy2('test_e2e.py', 'tests/e2e/test_e2e.py')
shutil.copy2('test_e2e.py', 'backend/tests/e2e/test_e2e.py')

shutil.copy2('test_all_apis.py', 'tests/e2e/test_all_apis.py')
shutil.copy2('benchmark_performance.py', 'tests/performance/benchmark_performance.py')

os.makedirs('tests/unit', exist_ok=True)
os.makedirs('tests/integration', exist_ok=True)
os.makedirs('tests/e2e', exist_ok=True)
os.makedirs('tests/performance', exist_ok=True)
os.makedirs('backend/tests/unit', exist_ok=True)
os.makedirs('backend/tests/integration', exist_ok=True)
os.makedirs('backend/tests/e2e', exist_ok=True)

# Security Audit unit test
with open('tests/unit/test_security_audit.py', 'w') as f:
    f.write('''import os, re

def test_passive_security():
    forbidden = [
        r'\\.send\\(', r'\\.sendp\\(', r'\\.sendto\\(', r'sr\\(', r'sr1\\(',
        r'iptables', r'nftables', r'tc qdisc', r'drop ', r'block ',
        r'decrypt\\(', r'AES\\.', r'RSA\\.', r'nmap'
    ]
    violations = []
    for root, dirs, files in os.walk('backend'):
        for file in files:
            if file.endswith('.py'):
                p = os.path.join(root, file)
                with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                    for idx, line in enumerate(fh, 1):
                        if line.strip().startswith('#'): continue
                        for pat in forbidden:
                            if re.search(pat, line):
                                violations.append((p, idx, line.strip()))
    assert len(violations) == 0, f"Violations found: {violations}"
    print("Zero active/intrusive network calls confirmed. Passive compliance PASS.")

if __name__ == "__main__":
    test_passive_security()
''')

# Backend unit test
with open('backend/tests/unit/test_schemas.py', 'w') as f:
    f.write('''from backend.app.schemas.flow import NormalizedFlow
from backend.app.schemas.alert import UnifiedAlert

def test_normalized_flow_creation():
    nf = NormalizedFlow(flow_id="test1", source_ip="192.168.1.10", destination_ip="8.8.8.8")
    assert nf.source_ip == "192.168.1.10"
    assert nf.total_packets == 0

def test_unified_alert():
    al = UnifiedAlert(prediction="BENIGN", severity="LOW", score=0.0)
    assert al.prediction == "BENIGN"
    assert al.severity == "LOW"

if __name__ == "__main__":
    test_normalized_flow_creation()
    test_unified_alert()
    print("Unit tests passed.")
''')

print('Test suites organized successfully.')
