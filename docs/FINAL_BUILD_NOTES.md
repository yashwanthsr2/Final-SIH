# Final build notes

## Verified during the final integration pass

- Bundled DDoS model remains unchanged.
- Bundled C2 model remains unchanged.
- Bundled DNS model remains unchanged.
- Bundled encrypted-traffic model remains unchanged.
- Production detector set remains exactly four families.
- Scapy + Npcap live capture is enabled.
- Live DNS input is guarded against tiny one/two-flow windows.
- Live DNS alerts require persistence across two consecutive windows before being stored as confirmed alerts.
- Dashboard uses “MODEL SCORE” instead of “CONFIDENCE”.
- Verified replay/demo endpoints remain separate from passive live capture.

## Important scientific wording

Use “model score” rather than “confidence” unless a score has been explicitly calibrated.

Use “suspicious encrypted communication/traffic detection based on observable metadata”. Do not claim payload malware identification or decryption.

C2 generalization is a known limitation and should be reported honestly; do not hide it behind accuracy.
