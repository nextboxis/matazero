"""Container structure anomaly detection per SRD FR-4.7."""

from __future__ import annotations
from collections import Counter
from typing import List, Optional
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import StructuralUnit


class ContainerAnomalyDetector:
    """Detects structural anomalies such as duplicate segments and illegal ordering."""

    @staticmethod
    def detect_anomalies(units: List[StructuralUnit], format_name: str) -> List[Finding]:
        findings: List[Finding] = []
        names = [u.name for u in units]
        counts = Counter(names)

        # Check for multiple SOF markers in JPEG
        sof_count = sum(c for name, c in counts.items() if name.startswith("SOF"))
        if format_name == "JPEG" and sof_count > 1:
            findings.append(
                Finding(
                    name="container_anomaly_multiple_sof",
                    value=f"Found {sof_count} SOF segments in single JPEG container",
                    tier=3,
                    extractor="container_anomaly_detector",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="artefact", extractor="container_anomaly_detector"),
                )
            )

        # Check for multiple IHDR chunks in PNG
        if format_name == "PNG" and counts.get("IHDR", 0) > 1:
            findings.append(
                Finding(
                    name="container_anomaly_duplicate_ihdr",
                    value=f"Found {counts['IHDR']} IHDR chunks in PNG container (illegal per ISO 15948)",
                    tier=3,
                    extractor="container_anomaly_detector",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="artefact", extractor="container_anomaly_detector"),
                )
            )

        return findings
