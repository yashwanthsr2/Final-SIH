"""
CyberSentinel Zeek Live Sensor Compatibility Shim.
Re-exports canonical implementation from backend.app.ingestion.zeek_ingest.
"""

from backend.app.ingestion.zeek_ingest import ZeekLiveSensor

__all__ = ["ZeekLiveSensor"]
