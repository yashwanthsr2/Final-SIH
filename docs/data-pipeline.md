# CyberSentinel Data Pipeline

## Data Flow
The platform supports 4 heterogeneous traffic inputs that converge into a unified flow model:
1. Live Wi-Fi sniffer (promiscuous mode, non-blocking)
2. Live Zeek sensor (tailing conn.log, dns.log, ssl.log)
3. Offline PCAP replay
4. Machine learning dataset replay (Parquet / CSV)

## Normalization
All inputs are transformed into `NormalizedFlow`, capturing:
- `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`
- Volume metrics: `orig_bytes`, `resp_bytes`, `total_bytes`, `orig_pkts`, `resp_pkts`
- State & History: `conn_state`, `history`, `duration`
- Application Metadata: `dns_query`, `tls_sni`, `service`
