"""
CyberSentinel Base Ingestion Interface.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Callable, Optional
from backend.app.schemas.flow import NormalizedFlow

class BaseIngestor(ABC):
    def __init__(self, callback: Callable[[NormalizedFlow], None]):
        self.callback = callback
        self.is_running = False

    @abstractmethod
    def start(self, **kwargs) -> bool:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass
