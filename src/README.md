# `src/` Directory Architecture Notice

> [!NOTE]
> **Canonical Detectors & Ingestion are in [`backend/app/`](../backend/app/)**

### Purpose of `src/`
The files in this directory (`src/detectors/`, `src/live_monitor.py`, `src/zeek_sensor.py`, etc.) are lightweight **backwards-compatibility shims**. 

They re-export the canonical implementations from:
- `src/detectors/c2_detector.py` ➔ [`backend.app.detectors.beaconing.c2_detector`](../backend/app/detectors/beaconing/c2_detector.py)
- `src/detectors/dos_detector.py` ➔ [`backend.app.detectors.ddos.dos_detector`](../backend/app/detectors/ddos/dos_detector.py)
- `src/detectors/dns_detector.py` ➔ [`backend.app.detectors.dga_dns.dns_detector`](../backend/app/detectors/dga_dns/dns_detector.py)
- `src/detectors/encrypted_detector.py` ➔ [`backend.app.detectors.encrypted_malware.encrypted_detector`](../backend/app/detectors/encrypted_malware/encrypted_detector.py)
- `src/detectors/recon_detector.py` ➔ [`backend.app.detectors.reconnaissance.recon_detector`](../backend/app/detectors/reconnaissance/recon_detector.py)
- `src/detectors/exfil_detector.py` ➔ [`backend.app.detectors.exfiltration.exfil_detector`](../backend/app/detectors/exfiltration/exfil_detector.py)
- `src/zeek_sensor.py` ➔ [`backend.app.ingestion.zeek_ingest.ZeekLiveSensor`](../backend/app/ingestion/zeek_ingest.py)
- `src/live_monitor.py` ➔ [`backend.app.ingestion.live_interface.LiveMonitor`](../backend/app/ingestion/live_interface.py)

### Development Guideline
Do not modify or implement business logic directly in `src/`. All new detector logic and ingestion enhancements must be committed in [`backend/app/`](../backend/app/).
