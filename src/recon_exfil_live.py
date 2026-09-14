"""
CODEZILLA LIVE RECONNAISSANCE + DATA EXFILTRATION INTEGRATION

This module extends the existing passive LiveMonitor without
rewriting its working DDoS/C2/DNS/encrypted-traffic logic.

Design:
    LiveMonitor
        |
        +--> existing four detectors
        |
        +--> Reconnaissance behavioral detector
        |
        +--> Data-transfer anomaly detector

The extension is passive/read-only.

It:
    - does not send packets
    - does not perform scans
    - does not decrypt payloads
    - does not modify captured traffic

It only uses already-observed Flow metadata.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps
from types import MethodType
from typing import Any, Callable, Dict, List, Tuple

from src.detectors.exfil_detector import (
    build_features as build_exfil_features,
)


# ============================================================
# TYPES
# ============================================================

DetectCallback = Callable[
    [Dict[str, Any]],
    Dict[str, Any],
]


# ============================================================
# HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """Safely convert a value to float."""

    try:
        return float(value)

    except (
        TypeError,
        ValueError,
    ):
        return default


def _clamp(
    value: float,
) -> float:
    """Clamp a value to 0..1."""

    return max(
        0.0,
        min(
            1.0,
            value,
        ),
    )


def _flow_duration(
    flow: Any,
) -> float:
    """Return observed flow duration."""

    first_ts = _safe_float(
        getattr(
            flow,
            "first_ts",
            0.0,
        )
    )

    last_ts = _safe_float(
        getattr(
            flow,
            "last_ts",
            first_ts,
        )
    )

    return max(
        0.0,
        last_ts - first_ts,
    )


# ============================================================
# FLOW GROUPING
# ============================================================

def _group_flows_by_source(
    flows: List[Any],
) -> Dict[str, List[Any]]:
    """
    Group observed flows by source address.

    This keeps the resulting alert tied to a concrete observed
    source rather than mixing unrelated hosts together.
    """

    grouped: Dict[
        str,
        List[Any],
    ] = defaultdict(list)

    for flow in flows:

        source = str(
            getattr(
                flow,
                "src",
                "unknown",
            )
        )

        grouped[
            source
        ].append(
            flow
        )

    return dict(
        grouped
    )


# ============================================================
# RECONNAISSANCE FEATURES
# ============================================================

def _build_recon_features(
    flows: List[Any],
    previous_flows: List[Any] | None = None,
) -> Dict[str, float]:
    """
    Build reconnaissance features from observed Flow metadata.

    These features are intentionally passive.

    The implementation focuses on:
        - destination host fan-out
        - destination port fan-out
        - connection attempts
        - failed connections
        - short-lived flows
        - fan-out changes
        - destination concentration
    """

    previous_flows = (
        previous_flows
        or []
    )

    flow_count = len(
        flows
    )

    if flow_count == 0:

        return {
            "unique_destination_hosts": 0.0,
            "unique_destination_ports": 0.0,
            "flow_count": 0.0,
            "connection_attempts": 0.0,
            "failed_connection_ratio": 0.0,
            "short_flow_ratio": 0.0,
            "port_fanout": 0.0,
            "host_fanout": 0.0,
            "fanout_change": 0.0,
            "destination_concentration": 0.0,
        }

    destinations = [
        str(
            getattr(
                flow,
                "dst",
                "unknown",
            )
        )
        for flow in flows
    ]

    ports = [
        int(
            _safe_float(
                getattr(
                    flow,
                    "dport",
                    0,
                )
            )
        )
        for flow in flows
    ]

    unique_destinations = set(
        destinations
    )

    unique_ports = {
        port
        for port in ports
        if port > 0
    }

    # --------------------------------------------------------
    # Connection attempts
    # --------------------------------------------------------

    connection_attempts = sum(
        max(
            0,
            int(
                _safe_float(
                    getattr(
                        flow,
                        "syn",
                        0,
                    )
                )
            ),
        )
        for flow in flows
    )

    # If the captured flow metadata does not expose SYN counts,
    # each flow itself is still a connection observation.

    if connection_attempts <= 0:

        connection_attempts = (
            flow_count
        )

    # --------------------------------------------------------
    # Failed connection approximation
    # --------------------------------------------------------

    failed_flows = 0

    for flow in flows:

        rst_count = max(
            0,
            int(
                _safe_float(
                    getattr(
                        flow,
                        "rst",
                        0,
                    )
                )
            ),
        )

        if rst_count > 0:
            failed_flows += 1

    failed_connection_ratio = (
        failed_flows
        / max(
            flow_count,
            1,
        )
    )

    # --------------------------------------------------------
    # Short-flow ratio
    # --------------------------------------------------------

    short_flows = sum(
        1
        for flow in flows
        if _flow_duration(flow) <= 1.0
    )

    short_flow_ratio = (
        short_flows
        / max(
            flow_count,
            1,
        )
    )

    # --------------------------------------------------------
    # Fan-out
    # --------------------------------------------------------

    host_fanout = (
        len(unique_destinations)
        / max(
            flow_count,
            1,
        )
    )

    port_fanout = (
        len(unique_ports)
        / max(
            len(unique_destinations),
            1,
        )
    )

    # --------------------------------------------------------
    # Destination concentration
    # --------------------------------------------------------

    destination_counts: Dict[
        str,
        int,
    ] = defaultdict(int)

    for destination in destinations:

        destination_counts[
            destination
        ] += 1

    dominant_destination_count = (
        max(
            destination_counts.values()
        )
        if destination_counts
        else 0
    )

    destination_concentration = (
        dominant_destination_count
        / max(
            flow_count,
            1,
        )
    )

    # --------------------------------------------------------
    # Fan-out change from previous window
    # --------------------------------------------------------

    previous_destinations = {
        str(
            getattr(
                flow,
                "dst",
                "unknown",
            )
        )
        for flow in previous_flows
    }

    previous_ports = {
        int(
            _safe_float(
                getattr(
                    flow,
                    "dport",
                    0,
                )
            )
        )
        for flow in previous_flows
        if int(
            _safe_float(
                getattr(
                    flow,
                    "dport",
                    0,
                )
            )
        ) > 0
    }

    previous_host_fanout = (
        len(previous_destinations)
        / max(
            len(previous_flows),
            1,
        )
    )

    previous_port_fanout = (
        len(previous_ports)
        / max(
            len(previous_destinations),
            1,
        )
    )

    current_combined_fanout = (
        host_fanout
        + port_fanout
    )

    previous_combined_fanout = (
        previous_host_fanout
        + previous_port_fanout
    )

    fanout_change = max(
        0.0,
        current_combined_fanout
        - previous_combined_fanout,
    )

    return {
        "unique_destination_hosts": float(
            len(unique_destinations)
        ),

        "unique_destination_ports": float(
            len(unique_ports)
        ),

        "flow_count": float(
            flow_count
        ),

        "connection_attempts": float(
            connection_attempts
        ),

        "failed_connection_ratio": round(
            _clamp(
                failed_connection_ratio
            ),
            4,
        ),

        "short_flow_ratio": round(
            _clamp(
                short_flow_ratio
            ),
            4,
        ),

        "port_fanout": round(
            max(
                0.0,
                port_fanout,
            ),
            4,
        ),

        "host_fanout": round(
            _clamp(
                host_fanout
            ),
            4,
        ),

        "fanout_change": round(
            max(
                0.0,
                fanout_change,
            ),
            4,
        ),

        "destination_concentration": round(
            _clamp(
                destination_concentration
            ),
            4,
        ),
    }


# ============================================================
# WINDOW SOURCE SELECTION
# ============================================================

def _recon_candidate(
    groups: Dict[str, List[Any]],
) -> Tuple[
    str | None,
    List[Any],
]:
    """
    Select the source showing the strongest reconnaissance-like
    fan-out pattern.
    """

    if not groups:

        return None, []

    def ranking(
        item: Tuple[
            str,
            List[Any],
        ],
    ) -> Tuple[
        float,
        float,
        float,
    ]:

        _source, flows = item

        destinations = {
            str(
                getattr(
                    flow,
                    "dst",
                    "unknown",
                )
            )
            for flow in flows
        }

        ports = {
            int(
                _safe_float(
                    getattr(
                        flow,
                        "dport",
                        0,
                    )
                )
            )
            for flow in flows
            if _safe_float(
                getattr(
                    flow,
                    "dport",
                    0,
                )
            ) > 0
        }

        syn_count = sum(
            _safe_float(
                getattr(
                    flow,
                    "syn",
                    0,
                )
            )
            for flow in flows
        )

        return (
            float(
                len(destinations)
            ),
            float(
                len(ports)
            ),
            float(
                syn_count
            ),
        )

    return max(
        groups.items(),
        key=ranking,
    )


def _exfil_candidate(
    groups: Dict[str, List[Any]],
) -> Tuple[
    str | None,
    List[Any],
]:
    """
    Select the source responsible for the largest observed
    byte volume in the window.
    """

    if not groups:

        return None, []

    def byte_total(
        item: Tuple[
            str,
            List[Any],
        ],
    ) -> float:

        _source, flows = item

        return sum(
            max(
                0.0,
                _safe_float(
                    getattr(
                        flow,
                        "bytes",
                        0,
                    )
                ),
            )
            for flow in flows
        )

    return max(
        groups.items(),
        key=byte_total,
    )


# ============================================================
# LIVE ATTACHMENT
# ============================================================

def attach_live_monitor(
    monitor: Any,
    detect_callback: DetectCallback,
) -> None:
    """
    Attach Reconnaissance and Data Exfiltration processing to the
    existing CODEZILLA LiveMonitor instance.

    Existing monitor behavior is preserved.

    The original _finalize_window() is still called normally.
    The two new detector payloads are generated immediately
    before the original finalization.
    """

    marker = (
        "_codezilla_recon_exfil_attached"
    )

    if getattr(
        monitor,
        marker,
        False,
    ):

        return

    # --------------------------------------------------------
    # Existing methods
    # --------------------------------------------------------

    original_start = (
        monitor.start
    )

    original_finalize = (
        monitor._finalize_window
    )

    # --------------------------------------------------------
    # History containers
    # --------------------------------------------------------

    monitor._codezilla_recon_previous = {}

    monitor._codezilla_exfil_previous = {}

    # --------------------------------------------------------
    # START WRAPPER
    # --------------------------------------------------------

    @wraps(
        original_start
    )
    def start_wrapper(
        self: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:

        self._codezilla_recon_previous = {}

        self._codezilla_exfil_previous = {}

        return original_start(
            *args,
            **kwargs,
        )

    monitor.start = MethodType(
        start_wrapper,
        monitor,
    )

    # --------------------------------------------------------
    # FINALIZE WRAPPER
    # --------------------------------------------------------

    @wraps(
        original_finalize
    )
    def finalize_wrapper(
        self: Any,
        force: bool = False,
    ) -> Any:

        # Capture the current flow objects BEFORE the existing
        # LiveMonitor finalizer clears its internal flow map.

        current_flow_map = getattr(
            self,
            "_flows",
            {},
        )

        flows = list(
            current_flow_map.values()
        )

        # ----------------------------------------------------
        # Extended detector processing
        # ----------------------------------------------------

        if flows:

            try:

                groups = (
                    _group_flows_by_source(
                        flows
                    )
                )

                (
                    recon_source,
                    recon_flows,
                ) = _recon_candidate(
                    groups
                )

                (
                    exfil_source,
                    exfil_flows,
                ) = _exfil_candidate(
                    groups
                )

                window_started = getattr(
                    self,
                    "_window_started",
                    None,
                )

                if window_started:

                    window_time = (
                        datetime.fromtimestamp(
                            window_started,
                            timezone.utc,
                        )
                        .replace(
                            microsecond=0
                        )
                        .isoformat()
                    )

                else:

                    window_time = (
                        datetime.now(
                            timezone.utc
                        )
                        .replace(
                            microsecond=0
                        )
                        .isoformat()
                    )

                window_seconds = max(
                    1.0,
                    _safe_float(
                        getattr(
                            self,
                            "default_window_seconds",
                            5.0,
                        ),
                        5.0,
                    ),
                )

                # ==========================================
                # RECONNAISSANCE
                # ==========================================

                recon_payload = None

                if recon_source is not None:

                    previous_recon = (
                        self._codezilla_recon_previous.get(
                            recon_source,
                            [],
                        )
                    )

                    recon_features = (
                        _build_recon_features(
                            recon_flows,
                            previous_recon,
                        )
                    )

                    recon_payload = {
                        "source": recon_source,
                        "time_window": window_time,
                        "recon_features": recon_features,
                    }

                    self._codezilla_recon_previous[
                        recon_source
                    ] = list(
                        recon_flows
                    )

                # ==========================================
                # DATA EXFILTRATION
                # ==========================================

                exfil_payload = None

                if exfil_source is not None:

                    previous_exfil = (
                        self._codezilla_exfil_previous.get(
                            exfil_source,
                            [],
                        )
                    )

                    exfil_features = (
                        build_exfil_features(
                            exfil_flows,
                            window_seconds=window_seconds,
                            previous_flows=previous_exfil,
                        )
                    )

                    exfil_payload = {
                        "source": exfil_source,
                        "time_window": window_time,
                        "exfil_features": exfil_features,
                    }

                    self._codezilla_exfil_previous[
                        exfil_source
                    ] = list(
                        exfil_flows
                    )

                # ==========================================
                # COMBINE WHEN SAME SOURCE
                # ==========================================

                if (
                    recon_payload is not None
                    and exfil_payload is not None
                    and recon_source
                    == exfil_source
                ):

                    combined_payload = {
                        "source": recon_source,
                        "time_window": window_time,
                        "recon_features": recon_payload[
                            "recon_features"
                        ],
                        "exfil_features": exfil_payload[
                            "exfil_features"
                        ],
                    }

                    detect_callback(
                        combined_payload
                    )

                else:

                    # Different sources are kept separate so
                    # evidence is never incorrectly attributed.

                    if recon_payload is not None:

                        detect_callback(
                            recon_payload
                        )

                    if exfil_payload is not None:

                        detect_callback(
                            exfil_payload
                        )

            except Exception:
                # The extended detectors must never break the
                # existing live DDoS/C2/DNS/encrypted pipeline.

                pass

        # ----------------------------------------------------
        # ALWAYS preserve original behavior
        # ----------------------------------------------------

        return original_finalize(
            force=force
        )

    monitor._finalize_window = MethodType(
        finalize_wrapper,
        monitor,
    )

    setattr(
        monitor,
        marker,
        True,
    )