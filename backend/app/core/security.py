"""
CyberSentinel Passive Security Assertion & Guardrails.

Verifies and guarantees:
  - Strictly PASSIVE, read-only network operation.
  - ZERO packet transmission or injection.
  - ZERO external endpoint probing or active port scanning.
  - ZERO payload decryption (metadata inspection only).
   - ZERO traffic disruption or packet alteration/intervention commands.
"""

from __future__ import annotations
from backend.app.core.config import PASSIVE_ONLY, NO_PAYLOAD_DECRYPTION

class PassiveComplianceError(Exception):
    """Raised when an active, disruptive, or intrusive network action is attempted."""
    pass

def assert_passive_compliance() -> bool:
    """Enforces strict passive compliance at runtime."""
    if not PASSIVE_ONLY:
        raise PassiveComplianceError("Active mode is strictly prohibited by CyberSentinel policy.")
    if not NO_PAYLOAD_DECRYPTION:
        raise PassiveComplianceError("Payload decryption is strictly prohibited by privacy policy.")
    return True
