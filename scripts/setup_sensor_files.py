import shutil

# Copy run_kali_sensor.sh
shutil.copy2('run_kali_sensor.sh', 'sensor/zeek/scripts/run_kali_sensor.sh')

# Zeek configs
with open('sensor/zeek/configs/local.zeek', 'w') as f:
    f.write('''# CyberSentinel Zeek Local Configuration
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
redef LogAscii::use_json = T;
''')

with open('sensor/zeek/configs/zeekctl.cfg', 'w') as f:
    f.write('''# CyberSentinel zeekctl configuration
MailTo = root@localhost
LogRotationInterval = 3600
''')

# Zeek parsers
with open('sensor/zeek/parsers/conn_parser.py', 'w') as f:
    f.write('''from backend.app.schemas.flow import NormalizedFlow
def parse_conn_log(row: dict) -> NormalizedFlow:
    return NormalizedFlow.from_zeek_conn(row)
''')

# Live capture interface manager
with open('sensor/live_capture/interface_manager.py', 'w') as f:
    f.write('''import psutil
from typing import List

def list_network_interfaces() -> List[str]:
    return list(psutil.net_if_addrs().keys())
''')

# Live capture sensor manager
with open('sensor/live_capture/sensor_manager.py', 'w') as f:
    f.write('''from backend.app.ingestion.zeek_ingest import ZeekLiveSensor
try:
    from backend.app.ingestion.live_interface import LiveMonitor
except Exception:
    LiveMonitor = None
''')

# Sensor README
shutil.copy2('KALI_LIVE_MONITORING_GUIDE.md', 'sensor/README.md')
print('Sensor subsystem initialized successfully.')
