"""
CyberSentinel Digital Twin Graph Engine.
In-memory network topology with node/edge scoring.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.config import TWIN_MAX_NODES, TWIN_NODE_TTL
from backend.app.digital_twin.nodes import NODE_TYPE_IP, NODE_TYPE_DOMAIN, NODE_TYPE_PORT, create_node

class DigitalTwin:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._events: deque = deque(maxlen=200)

    def _ensure_node(self, node_id: str, node_type: str) -> Dict[str, Any]:
        if node_id not in self._nodes:
            self._nodes[node_id] = create_node(node_id, node_type)
        return self._nodes[node_id]

    def update_from_flow(
        self,
        *,
        src_ip: str,
        dst_ip: Optional[str] = None,
        domain: Optional[str] = None,
        dst_port: Optional[int] = None,
        packets: int = 0,
        bytes_count: int = 0,
        threat_score: float = 0.0,
        threat_class: Optional[str] = None,
    ) -> None:
        with self._lock:
            now = time.time()
            src_node = self._ensure_node(src_ip, NODE_TYPE_IP)
            src_node["last_seen"] = now
            src_node["packets"] += packets
            src_node["bytes"] += bytes_count
            src_node["flow_count"] += 1
            if threat_score > src_node["threat_score"]:
                src_node["threat_score"] = threat_score
            if threat_class and threat_class not in src_node["threat_classes"]:
                src_node["threat_classes"].append(threat_class)

            edge_target = None
            if dst_ip:
                dst_node = self._ensure_node(dst_ip, NODE_TYPE_IP)
                dst_node["last_seen"] = now
                dst_node["bytes"] += bytes_count
                dst_node["flow_count"] += 1
                edge_target = dst_ip

            if domain:
                dom_node = self._ensure_node(domain, NODE_TYPE_DOMAIN)
                dom_node["last_seen"] = now
                dom_node["flow_count"] += 1
                if threat_score > dom_node["threat_score"]:
                    dom_node["threat_score"] = threat_score
                if threat_class and threat_class not in dom_node["threat_classes"]:
                    dom_node["threat_classes"].append(threat_class)
                edge_target = domain

            if dst_port:
                port_id = f"port:{dst_port}"
                port_node = self._ensure_node(port_id, NODE_TYPE_PORT)
                port_node["last_seen"] = now
                port_node["flow_count"] += 1

            if edge_target:
                edge_key = (src_ip, edge_target)
                if edge_key not in self._edges:
                    self._edges[edge_key] = {
                        "src": src_ip,
                        "dst": edge_target,
                        "packets": 0,
                        "bytes": 0,
                        "flow_count": 0,
                        "last_seen": now,
                        "threat_score": 0.0,
                        "threat_class": None,
                    }
                edge = self._edges[edge_key]
                edge["packets"] += packets
                edge["bytes"] += bytes_count
                edge["flow_count"] += 1
                edge["last_seen"] = now
                if threat_score > edge["threat_score"]:
                    edge["threat_score"] = threat_score
                    edge["threat_class"] = threat_class

            self._evict_stale()

    def update_threat_score(self, node_id: str, threat_score: float, threat_class: str) -> None:
        with self._lock:
            if node_id in self._nodes:
                node = self._nodes[node_id]
                if threat_score > node["threat_score"]:
                    node["threat_score"] = threat_score
                if threat_class and threat_class not in node["threat_classes"]:
                    node["threat_classes"].append(threat_class)

    def _evict_stale(self) -> None:
        now = time.time()
        stale_cutoff = now - TWIN_NODE_TTL
        stale = [nid for nid, n in self._nodes.items() if n["last_seen"] < stale_cutoff]
        for nid in stale:
            self._nodes.pop(nid, None)

        stale_edges = [k for k in self._edges if k[0] not in self._nodes or k[1] not in self._nodes]
        for k in stale_edges:
            self._edges.pop(k, None)

        if len(self._nodes) > TWIN_MAX_NODES:
            sorted_nodes = sorted(self._nodes.items(), key=lambda x: x[1]["last_seen"])
            to_remove = len(self._nodes) - TWIN_MAX_NODES
            for nid, _ in sorted_nodes[:to_remove]:
                self._nodes.pop(nid, None)

    def get_graph(
        self,
        include_ports: bool = False,
        min_threat_score: float = 0.0,
        limit_nodes: int = 150,
    ) -> Dict[str, Any]:
        with self._lock:
            nodes = []
            for node in self._nodes.values():
                if node["node_type"] == NODE_TYPE_PORT and not include_ports:
                    continue
                if node["threat_score"] < min_threat_score and min_threat_score > 0:
                    continue
                nodes.append({
                    "id": node["id"],
                    "type": node["node_type"],
                    "threat_score": round(node["threat_score"], 3),
                    "threat_classes": node["threat_classes"],
                    "flow_count": node["flow_count"],
                    "bytes": node["bytes"],
                    "packets": node.get("packets", 0),
                    "first_seen": node.get("first_seen", node["last_seen"]),
                    "last_seen": node["last_seen"],
                    "is_suspicious": node["threat_score"] >= 0.5,
                })

            nodes.sort(key=lambda n: n["threat_score"], reverse=True)
            nodes = nodes[:limit_nodes]
            node_ids = {n["id"] for n in nodes}

            edges = []
            for edge in self._edges.values():
                if edge["src"] not in node_ids or edge["dst"] not in node_ids:
                    continue
                edges.append({
                    "src": edge["src"],
                    "dst": edge["dst"],
                    "flow_count": edge["flow_count"],
                    "bytes": edge["bytes"],
                    "packets": edge.get("packets", 0),
                    "threat_score": round(edge["threat_score"], 3),
                    "threat_class": edge["threat_class"],
                    "is_suspicious": edge["threat_score"] >= 0.5,
                    "last_seen": edge.get("last_seen", 0.0),
                })

            return {
                "nodes": nodes,
                "edges": edges,
                "node_count": len(nodes),
                "edge_count": len(edges),
            }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            suspicious_nodes = sum(
                1 for n in self._nodes.values() if n["threat_score"] >= 0.5
            )
            return {
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
                "suspicious_nodes": suspicious_nodes,
                "ip_nodes": sum(1 for n in self._nodes.values() if n["node_type"] == NODE_TYPE_IP),
                "domain_nodes": sum(1 for n in self._nodes.values() if n["node_type"] == NODE_TYPE_DOMAIN),
            }

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            if hasattr(self, "_events"):
                self._events.clear()

_twin: Optional[DigitalTwin] = None
_twin_lock = threading.Lock()

def get_twin() -> DigitalTwin:
    global _twin
    if _twin is None:
        with _twin_lock:
            if _twin is None:
                _twin = DigitalTwin()
                # Seed default internal nodes
                _twin.update_from_flow(src_ip="192.168.1.1", dst_ip="192.168.1.50")
                _twin.update_from_flow(src_ip="192.168.1.50", dst_ip="8.8.8.8", dst_port=53)
    return _twin
