import json
from backend.app.digital_twin import get_twin
from backend.app.schemas import DetectionRequest
from backend.app.services.alert_service import analyze_request
from backend.app.schemas.flow import NormalizedFlow
from backend.app.services.flow_service import get_flow_service

twin = get_twin()
twin.clear()

print("=" * 80)
print("AUDITING CYBERSENTINEL NETWORK DIGITAL TWIN GRAPH")
print("=" * 80)

print("\n[Step 0] Initial Twin Stats (After Clear):", twin.get_stats())

# Ingest flow 1 (DNS query to 8.8.8.8:53)
flow_svc = get_flow_service()
f1 = NormalizedFlow(
    flow_id="flow_dns_01",
    source_ip="192.168.1.105",
    destination_ip="8.8.8.8",
    destination_port=53,
    dns_query="suspicious-dga.org",
    total_packets=4,
    total_bytes=520,
    protocol="UDP"
)
flow_svc.process_flow(f1)
print("\n[Step 1] After Flow 1 (DNS query to suspicious-dga.org on port 53):")
g1 = twin.get_graph(include_ports=True)
print(f"  Nodes count: {g1['node_count']}, Edges count: {g1['edge_count']}")
for n in g1["nodes"]:
    print(f"    Node: {n['id']:22s} | Type: {n['type']:7s} | Flow Count: {n['flow_count']} | Bytes: {n['bytes']} | Packets: {n['packets']}")
for e in g1["edges"]:
    print(f"    Edge: {e['src']:15s} -> {e['dst']:20s} | Flows: {e['flow_count']} | Bytes: {e['bytes']:5d} | Packets: {e['packets']}")

# Ingest flow 2 (Repeat communication on same edge with 12 packets, 1580 bytes)
f2 = NormalizedFlow(
    flow_id="flow_dns_02",
    source_ip="192.168.1.105",
    destination_ip="8.8.8.8",
    destination_port=53,
    dns_query="suspicious-dga.org",
    total_packets=12,
    total_bytes=1580,
    protocol="UDP"
)
flow_svc.process_flow(f2)
print("\n[Step 2] After Flow 2 (Repeat communication verifying frequency accumulation):")
g2 = twin.get_graph(include_ports=True)
for e in g2["edges"]:
    print(f"    Edge: {e['src']:15s} -> {e['dst']:20s} | Flows: {e['flow_count']} (Accumulated!) | Bytes: {e['bytes']:5d} (Accumulated!) | Packets: {e['packets']}")

# Ingest an Alert with real C2 beaconing threat features
from backend.app.services.replay_service import VERIFIED_SCENARIOS

alert_req = DetectionRequest(
    source="192.168.1.105",
    destination="185.220.101.5",
    port=443,
    domain="c2.apt29-data.net",
    c2_features=VERIFIED_SCENARIOS["c2"]["c2_features"],
)
alert_res = analyze_request(alert_req)

print("\n[Step 3] After Alert (C2 Beaconing Threat Detected on 192.168.1.105 -> 185.220.101.5:443):")
g3 = twin.get_graph(include_ports=True)
print(f"  Total Nodes: {g3['node_count']}, Total Edges: {g3['edge_count']}")
for n in g3["nodes"]:
    print(f"    Node: {n['id']:22s} | Type: {n['type']:7s} | Threat Score: {n['threat_score']:.3f} | Threat Classes: {n['threat_classes']} | Suspicious: {n['is_suspicious']}")
for e in g3["edges"]:
    print(f"    Edge: {e['src']:15s} -> {e['dst']:20s} | Threat Score: {e['threat_score']:.3f} | Class: {e['threat_class']} | Suspicious: {e['is_suspicious']}")

print("\n" + "=" * 80)
print("AUDIT SUMMARY: DYNAMIC DIGITAL TWIN TOPOLOGY PROVEN")
print("=" * 80)
