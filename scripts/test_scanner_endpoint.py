import urllib.request, json, uuid

# 1. Test File Upload (Benign JSON)
boundary = '----WebKitFormBoundary' + uuid.uuid4().hex
payload = (
    f'--{boundary}\r\n'
    'Content-Disposition: form-data; name="file"; filename="telemetry.json"\r\n'
    'Content-Type: application/json\r\n\r\n'
    '{"service": "CyberSentinel", "status": "ok", "healthy": true}\r\n'
    f'--{boundary}--\r\n'
).encode('utf-8')

req = urllib.request.Request('http://127.0.0.1:8000/api/scan/file',
    data=payload,
    headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
    method='POST')
res = json.loads(urllib.request.urlopen(req).read().decode())
print('File Upload Test (Benign):', res['verdict'], '| Threat:', res['threat_class'], '| Conf:', res['confidence'], '| Risk:', res['risk_score'], '| Entropy:', res['entropy'])

# 2. Test File Upload (High Entropy Compressed/Encrypted)
import os
random_bytes = os.urandom(1024)
boundary2 = '----WebKitFormBoundary' + uuid.uuid4().hex
payload2 = (
    f'--{boundary2}\r\n'
    'Content-Disposition: form-data; name="file"; filename="packed_sample.bin"\r\n'
    'Content-Type: application/octet-stream\r\n\r\n'
).encode('utf-8') + random_bytes + f'\r\n--{boundary2}--\r\n'.encode('utf-8')

req2 = urllib.request.Request('http://127.0.0.1:8000/api/scan/file',
    data=payload2,
    headers={'Content-Type': f'multipart/form-data; boundary={boundary2}'},
    method='POST')
res2 = json.loads(urllib.request.urlopen(req2).read().decode())
print('File Upload Test (High Entropy):', res2['verdict'], '| Threat:', res2['threat_class'], '| Conf:', res2['confidence'], '| Risk:', res2['risk_score'], '| Entropy:', res2['entropy'])
for ev in res2['evidence']:
    print('   -', ev['human_label'])
