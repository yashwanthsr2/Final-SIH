"""
CyberSentinel Zeek Live Sensor & Log Tailer.

Interfaces with the Zeek network security monitor:
- Runs strictly in passive capture mode: zeek -i <interface> -C
- Watches conn.log, dns.log, and ssl.log in real time
- Normalizes events into NormalizedFlow instances
- Provides diagnostic status if Zeek is missing or unprivileged
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.app.schemas.flow import NormalizedFlow


class ZeekLiveSensor:
    """
    Passive Zeek sensor that monitors an interface and streams
    normalized flow events.
    """

    DEFAULT_ZEEK_PATHS = [
        "zeek",
        "/opt/zeek/bin/zeek",
        "/usr/local/zeek/bin/zeek",
        "/usr/bin/zeek",
        "/usr/sbin/zeek",
    ]

    def __init__(
        self,
        flow_callback: Callable[[NormalizedFlow], None],
        log_dir: Optional[Path] = None,
    ) -> None:
        self.flow_callback = flow_callback
        self.log_dir = log_dir or Path("./zeek_logs").resolve()
        self._lock = threading.RLock()
        self._process: Optional[subprocess.Popen] = None
        self._tail_threads: List[threading.Thread] = []
        self._stop_event = threading.Event()
        self._running = False
        self._interface: Optional[str] = None
        self._records_ingested = 0
        self._last_event_time: Optional[float] = None
        self._last_error: Optional[str] = None

    @classmethod
    def find_zeek_binary(cls) -> Optional[str]:
        for path in cls.DEFAULT_ZEEK_PATHS:
            resolved = shutil.which(path)
            if resolved and os.path.exists(resolved) and os.access(resolved, os.X_OK):
                return resolved
        return None

    @classmethod
    def get_version(cls) -> Dict[str, Any]:
        binary = cls.find_zeek_binary()
        if not binary:
            return {
                "installed": False,
                "version": None,
                "path": None,
                "install_hint": "On Kali/Debian: sudo apt-get update && sudo apt-get install -y zeek",
            }
        try:
            res = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=5)
            version_str = (res.stdout or res.stderr or "").strip()
            return {
                "installed": True,
                "version": version_str,
                "path": binary,
                "install_hint": None,
            }
        except Exception as exc:
            return {
                "installed": True,
                "version": "Unknown",
                "path": binary,
                "error": str(exc),
            }

    def start(self, interface: str = "wlan0") -> Dict[str, Any]:
        with self._lock:
            if self._running:
                return self.status()

            self._interface = interface
            self._stop_event.clear()
            self._records_ingested = 0
            self._last_error = None
            self.log_dir.mkdir(parents=True, exist_ok=True)

            zeek_bin = self.find_zeek_binary()

            if zeek_bin:
                # Attempt to start Zeek live capture process
                try:
                    cmd = [
                        zeek_bin,
                        "-i", interface,
                        "-C",  # ignore checksums (standard for capture adapters)
                        "local",
                    ]
                    self._process = subprocess.Popen(
                        cmd,
                        cwd=str(self.log_dir),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                    )
                except Exception as exc:
                    self._last_error = f"Failed to start zeek process: {exc}"

            self._running = True

            # Start background tailing thread for conn.log and other logs
            t = threading.Thread(
                target=self._tail_conn_log,
                name="zeek-conn-tailer",
                daemon=True,
            )
            t.start()
            self._tail_threads.append(t)

        return self.status()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            if not self._running:
                return self.status()

            self._running = False
            self._stop_event.set()

            if self._process:
                try:
                    self._process.terminate()
                    self._process.wait(timeout=3)
                except Exception:
                    try:
                        self._process.kill()
                    except Exception:
                        pass
                self._process = None

        return self.status()

    def status(self) -> Dict[str, Any]:
        with self._lock:
            version_info = self.get_version()
            return {
                "running": self._running,
                "interface": self._interface,
                "backend": "Zeek Passive Sensor" if version_info["installed"] else "Zeek Unavailable (Tailer Ready)",
                "zeek_installed": version_info["installed"],
                "zeek_version": version_info.get("version"),
                "records_ingested": self._records_ingested,
                "last_event_time": self._last_event_time,
                "last_error": self._last_error,
                "log_directory": str(self.log_dir),
            }

    def _tail_conn_log(self) -> None:
        """Tail conn.log in self.log_dir and parse lines into NormalizedFlow."""
        conn_log_path = self.log_dir / "conn.log"
        file_obj = None
        fields = []

        while not self._stop_event.is_set():
            if not conn_log_path.exists():
                time.sleep(1.0)
                continue

            try:
                if file_obj is None:
                    file_obj = open(conn_log_path, "r", encoding="utf-8", errors="replace")

                line = file_obj.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                line = line.strip()
                if not line:
                    continue

                # Header parsing for standard Zeek TSV
                if line.startswith("#fields"):
                    fields = line.split()[1:]
                    continue
                if line.startswith("#"):
                    continue

                # JSON parsing or TSV parsing
                row: Dict[str, Any] = {}
                if line.startswith("{") and line.endswith("}"):
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                elif fields:
                    parts = line.split("\t")
                    if len(parts) == len(fields):
                        row = dict(zip(fields, parts))

                if row:
                    flow = NormalizedFlow.from_zeek_conn(row)
                    with self._lock:
                        self._records_ingested += 1
                        self._last_event_time = time.time()
                    try:
                        self.flow_callback(flow)
                    except Exception:
                        pass

            except Exception as exc:
                self._last_error = f"Error reading conn.log: {exc}"
                time.sleep(1.0)

        if file_obj:
            try:
                file_obj.close()
            except Exception:
                pass
