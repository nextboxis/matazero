"""Tests for Timeline Reconstruction and Clock Drift."""

import pytest
import time
from pathlib import Path
from PIL import Image
from imgint.core.timeline import TimelineReconstructor, TimelineExporter


@pytest.fixture
def multiple_evidence_files(tmp_path):
    p1 = tmp_path / "IMG_0001.jpg"
    p2 = tmp_path / "IMG_0002.jpg"
    p3 = tmp_path / "IMG_0003.jpg"

    Image.new("RGB", (30, 30), color="white").save(p1, "JPEG")
    time.sleep(0.02)
    Image.new("RGB", (30, 30), color="gray").save(p2, "JPEG")
    time.sleep(0.02)
    Image.new("RGB", (30, 30), color="black").save(p3, "JPEG")

    return [p1, p2, p3]


def test_timeline_reconstruction(multiple_evidence_files):
    report = TimelineReconstructor.reconstruct(multiple_evidence_files)
    assert report.total_events == 3
    assert len(report.events) == 3
    assert report.events[0].file_name == "IMG_0001.jpg"
    assert report.events[1].file_name == "IMG_0002.jpg"
    assert report.events[2].file_name == "IMG_0003.jpg"


def test_timeline_plaso_export(multiple_evidence_files):
    report = TimelineReconstructor.reconstruct(multiple_evidence_files)
    csv_str = TimelineExporter.to_plaso_csv(report)
    assert "datetime,timestamp_desc" in csv_str
    assert "IMG_0001.jpg" in csv_str
    assert "matazero_timeline" in csv_str
