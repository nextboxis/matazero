"""Built-in event subscribers for auditing, alerts, and quarantine logging."""

from __future__ import annotations
from typing import List, Optional

from imgint.core.event.events import (
    AnalysisStartedEvent,
    AnalysisCompletedEvent,
    AnomalyDetectedEvent,
    PayloadCarvedEvent,
    VerdictEvaluatedEvent,
)
from imgint.core.governance.audit import AuditLogger


class AuditLoggerSubscriber:
    """Subscriber that writes audit events into the cryptographic hash-chained audit log."""

    def __init__(self, audit_logger: Optional[AuditLogger] = None) -> None:
        self.audit_logger = audit_logger

    def on_analysis_completed(self, event: AnalysisCompletedEvent) -> None:
        if self.audit_logger:
            self.audit_logger.log_operation(
                operation="ANALYSIS_COMPLETED",
                target_path=event.file_path,
                details=f"SHA-256: {event.sha256} | Findings: {event.findings_count}",
            )

    def on_payload_carved(self, event: PayloadCarvedEvent) -> None:
        if self.audit_logger:
            self.audit_logger.log_operation(
                operation="PAYLOAD_CARVED",
                target_path=event.file_path,
                details=f"Type: {event.payload_type} | Size: {event.size_bytes}B -> {event.destination_path}",
            )


class AlertCollectorSubscriber:
    """Collects high-risk alerts during batch analysis runs."""

    def __init__(self) -> None:
        self.alerts: List[AnomalyDetectedEvent] = []

    def on_anomaly_detected(self, event: AnomalyDetectedEvent) -> None:
        if event.risk_level in ("HIGH", "CRITICAL"):
            self.alerts.append(event)
