# CODEZILLA — Modern 2025 Validation Layer

## Dataset selected
UWF-ZeekDataSum2025-1 and UWF-ZeekDataSum2025-2, University of West Florida.

These are modern Zeek Conn datasets released through the UWF dataset portal and used in 2025/2026 research on MITRE ATT&CK-labeled network traffic. Sum25-1 contains Benign, Reconnaissance, Discovery, Initial Access, Lateral Movement, Privilege Escalation, and Defense Evasion; Sum25-2 contains Benign, Reconnaissance, and Discovery.

Official data portal:
https://datasets.uwf.edu/data/

Official folders:
https://datasets.uwf.edu/data/UWF-ZeekDataSum25-1/csv/
https://datasets.uwf.edu/data/UWF-ZeekDataSum25-2/csv/

## Why this is being added
This layer does NOT replace the existing CIC-IDS-2018 / CTU-13 production models. It gives CODEZILLA a modern-data benchmark and an independently trained modern model for comparison.

That produces a stronger competition story:

1. Existing production detectors remain reproducible on the established benchmarks.
2. Modern 2025 Zeek data is evaluated separately.
3. The comparison is reported without mixing incompatible feature schemas.

## Expected raw structure
The UWF Zeek datasets use a 17-feature Conn representation. Important fields include:
`community_id`, `conn_state`, `duration`, `history`, `src_ip_zeek`, `src_port_zeek`, `dest_ip_zeek`, `dest_port_zeek`, `local_orig`, `local_resp`, `missed_bytes`, `orig_bytes`, `orig_ip_bytes`, `orig_pkts`, `resp_bytes`, `resp_ip_bytes`, `resp_pkts`, `service`, and `ts`.

The validation script only uses network-behaviour features and excludes IP addresses and timestamps from model features to reduce leakage and improve portability.
