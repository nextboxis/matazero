"""Tests for Forensic Event Bus and Pub-Sub engine."""

import pytest
from imgint.core.event import (
    ForensicEventBus,
    AnalysisStartedEvent,
    AnalysisCompletedEvent,
    AnomalyDetectedEvent,
    AlertCollectorSubscriber,
)


def test_event_bus_pub_sub():
    bus = ForensicEventBus()
    received = []

    def handler(evt: AnalysisStartedEvent):
        received.append(evt.file_path)

    bus.subscribe(AnalysisStartedEvent, handler)
    bus.publish(AnalysisStartedEvent(file_path="/evidence/test1.jpg"))

    assert len(received) == 1
    assert received[0] == "/evidence/test1.jpg"


def test_priority_dispatch():
    bus = ForensicEventBus()
    order = []

    bus.subscribe(AnalysisCompletedEvent, lambda e: order.append("second"), priority=50)
    bus.subscribe(AnalysisCompletedEvent, lambda e: order.append("first"), priority=10)
    bus.subscribe(AnalysisCompletedEvent, lambda e: order.append("third"), priority=100)

    bus.publish(AnalysisCompletedEvent(file_path="/evidence/test2.jpg"))
    assert order == ["first", "second", "third"]


def test_alert_collector():
    collector = AlertCollectorSubscriber()
    collector.on_anomaly_detected(
        AnomalyDetectedEvent(
            file_path="/evidence/bad.jpg",
            finding_name="trailing_payload",
            risk_level="HIGH",
            detail="Embedded PE binary found in trailer",
        )
    )
    collector.on_anomaly_detected(
        AnomalyDetectedEvent(
            file_path="/evidence/ok.jpg",
            finding_name="normal_tag",
            risk_level="LOW",
        )
    )

    assert len(collector.alerts) == 1
    assert collector.alerts[0].risk_level == "HIGH"
