"""Strongly typed forensic event definitions for matazero event bus."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ForensicEvent:
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = "GENERIC_EVENT"


@dataclass
class AnalysisStartedEvent(ForensicEvent):
    file_path: str = ""
    event_type: str = "ANALYSIS_STARTED"


@dataclass
class AnalysisCompletedEvent(ForensicEvent):
    file_path: str = ""
    sha256: str = ""
    mime_type: str = ""
    findings_count: int = 0
    event_type: str = "ANALYSIS_COMPLETED"


@dataclass
class AnomalyDetectedEvent(ForensicEvent):
    file_path: str = ""
    sha256: str = ""
    finding_name: str = ""
    tier: int = 0
    risk_level: str = "MEDIUM"
    detail: str = ""
    event_type: str = "ANOMALY_DETECTED"


@dataclass
class PayloadCarvedEvent(ForensicEvent):
    file_path: str = ""
    sha256: str = ""
    payload_type: str = ""
    offset: int = 0
    size_bytes: int = 0
    destination_path: str = ""
    event_type: str = "PAYLOAD_CARVED"


@dataclass
class VerdictEvaluatedEvent(ForensicEvent):
    file_path: str = ""
    sha256: str = ""
    verdict_label: str = ""
    confidence_score: float = 0.5
    risk_level: str = "LOW"
    event_type: str = "VERDICT_EVALUATED"
