"""Tests for Evidence Dataset Clustering and Outlier Triage."""

import pytest
from pathlib import Path
from PIL import Image
from imgint.core.cluster import ClusterEngine


@pytest.fixture
def sample_fleet(tmp_path):
    files = []
    # Create 4 similar JPEGs (Fleet A)
    for i in range(4):
        p = tmp_path / f"canon_{i}.jpg"
        Image.new("RGB", (50, 50), color=(10 * i, 100, 200)).save(p, "JPEG", quality=90)
        files.append(p)

    # Create 1 different image (Outlier)
    p_outlier = tmp_path / "png_outlier.png"
    Image.new("RGB", (50, 50), color="red").save(p_outlier, "PNG")
    files.append(p_outlier)

    return files


def test_camera_fleet_clustering(sample_fleet):
    report = ClusterEngine.cluster(sample_fleet, strategy="camera")
    assert report.total_images == 5
    assert len(report.clusters) >= 2


def test_dqt_clustering(sample_fleet):
    report = ClusterEngine.cluster(sample_fleet, strategy="dqt")
    assert report.total_images == 5
    assert len(report.clusters) >= 2


def test_outlier_detection(sample_fleet):
    report = ClusterEngine.cluster(sample_fleet, strategy="dqt")
    # png_outlier should be detected as an outlier
    assert len(report.outliers) >= 1
    outlier_names = [o.file_name for o in report.outliers]
    assert "png_outlier.png" in outlier_names
