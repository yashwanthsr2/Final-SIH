# CODEZILLA CyberSentinel — Final SIH Build

Passive, metadata-first, multi-detector network threat detection for the SIH26-26145 problem statement.

## Active production detectors

1. DDoS — HistGradientBoosting, bundled `models/dos_hgb.joblib`
2. C2 / Botnet Beaconing — HistGradientBoosting, bundled `models/c2_hgb.joblib`
3. DNS — HistGradientBoosting, bundled `models/dns_hgb.joblib`
4. Suspicious encrypted communication — HistGradientBoosting, bundled `models/encrypted_hgb.joblib`

The project does not decrypt payloads, probe endpoints, inject packets, block traffic, or send mitigation commands.

## Windows quick start

Use **Python 3.12**. The bundled serialized models are tested with **scikit-learn 1.5.1**.

```powershell
cd E:\CODEZILLA-SIH26145
& .\.venv312\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open:

`http://127.0.0.1:8000/`

## API checks

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/live/interfaces
Invoke-RestMethod -Method Post http://127.0.0.1:8000/demo/run-all
```

## Live capture

Install Npcap and run the API from an elevated or otherwise permitted Windows session.

```powershell
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/live/start?interface=%5CDevice%5CNPF_%7BAA323734-1F73-4910-8F49-CB84D2E9E48D%7D'
Invoke-RestMethod http://127.0.0.1:8000/live/status
Invoke-RestMethod -Method Post http://127.0.0.1:8000/live/stop
```

The live path is passive and uses Scapy + Npcap. Live DNS alerts use a small input-quality guard and persistence confirmation; this does not modify the trained DNS model or its 0.93 threshold. A DNS live candidate must persist across two consecutive windows before it is stored as a confirmed alert.

## Verified demo

The demo endpoints use the packaged verification artifacts under `evaluation/packaging/` and are not attack generation. They exercise the same detector service used by the API.

## Project structure

- `app/` — FastAPI service and dashboard
- `src/` — feature construction, live monitor, detector wrappers, fusion
- `models/` — bundled production model artifacts and schemas
- `evaluation/` — validation reports and reproducible demo inputs
- `scripts/` — modern-data validation/report tooling
- `notebooks/` — ML research and packaging notebooks

Raw training datasets and local Python virtual environments are intentionally not bundled; they are not required to run the packaged application or verified demos.
