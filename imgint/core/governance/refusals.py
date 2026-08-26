"""Enforcement of binding non-goals and refused capabilities per SRD GR-3.1 - GR-3.8."""

from typing import Set

REFUSED_CAPABILITIES = {
    "biometric_face_recognition": "Face recognition, face matching, or biometric identification is refused under GDPR Art. 9.",
    "bulk_platform_scraping": "Scraping or bulk collection from online platforms is refused.",
    "identity_correlation": "Automated cross-platform identity correlation of private individuals is refused.",
    "realtime_location_tracking": "Real-time or continuous location tracking of persons is refused.",
    "external_hash_db_query": "Matching against external surveillance/hash databases (PhotoDNA and equivalents) is out of scope and refused.",
    "authenticity_verdict": "Emitting boolean verdicts on authenticity or manipulation is prohibited. Only structured findings with confidence and caveats are permitted.",
}


class RefusalError(Exception):
    """Raised when an operation attempts to invoke a refused capability."""
    def __init__(self, capability: str, reason: str):
        super().__init__(f"Refused capability [{capability}]: {reason}")
        self.capability = capability
        self.reason = reason


def enforce_refusals(requested_capabilities: Set[str]) -> None:
    """Verifies that no requested operation or configuration invokes a refused capability."""
    for cap in requested_capabilities:
        if cap in REFUSED_CAPABILITIES:
            raise RefusalError(cap, REFUSED_CAPABILITIES[cap])
