"""
CyberSentinel CSV & Parquet Ingestion Streamer.
"""

from __future__ import annotations
import time
from pathlib import Path
from typing import Callable, Generator, List, Optional
import pandas as pd
from backend.app.schemas.flow import NormalizedFlow
from backend.app.ingestion.base import BaseIngestor

class CSVIngestor(BaseIngestor):
    def __init__(self, callback: Callable[[NormalizedFlow], None]):
        super().__init__(callback)

    def start(self, file_path: Path, delay: float = 0.05) -> bool:
        self.is_running = True
        df = pd.read_parquet(file_path) if str(file_path).endswith(".parquet") else pd.read_csv(file_path)
        for _, row in df.iterrows():
            if not self.is_running:
                break
            flow = NormalizedFlow.from_zeek_conn(row.to_dict())
            self.callback(flow)
            if delay > 0:
                time.sleep(delay)
        return True

    def stop(self) -> None:
        self.is_running = False
