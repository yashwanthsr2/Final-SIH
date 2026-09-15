# CyberSentinel Live Passive Wi-Fi Monitoring

## Requirements
- Host: Kali Linux / Ubuntu 22.04 / Debian
- Permissions: Elevated root access for socket capture (`sudo`)
- Network: Promiscuous mode on Wi-Fi interface (e.g. `wlan0`)

## Usage
```bash
chmod +x run_kali_sensor.sh
sudo ./run_kali_sensor.sh wlan0 http://127.0.0.1:8000
```
