"""Tests for Steganography and Bitplane Slicing."""

import pytest
from pathlib import Path
from PIL import Image
import numpy as np
from imgint.core.stego import StegoInspector


@pytest.fixture
def clean_image(tmp_path):
    p = tmp_path / "clean.png"
    img = Image.new("RGB", (40, 40), color="blue")
    img.save(p, "PNG")
    return p


@pytest.fixture
def simulated_stego_image(tmp_path):
    p = tmp_path / "stego.png"
    arr = np.zeros((64, 64, 3), dtype=np.uint8)
    # Fill with gradient
    for i in range(64):
        for j in range(64):
            arr[i, j] = [i * 3, j * 3, (i + j) * 2]
    # Overwrite LSB of all channels with random noise (pseudo-encrypted payload)
    np.random.seed(42)
    rand_lsb = np.random.randint(0, 2, (64, 64, 3), dtype=np.uint8)
    arr = (arr & np.uint8(0xFE)) | rand_lsb
    img = Image.fromarray(arr)
    img.save(p, "PNG")
    return p


def test_clean_image_stego(clean_image):
    res = StegoInspector.inspect(clean_image)
    assert res.stego_risk_score <= 0.5
    assert "CLEAN" in res.stego_verdict or "LOW" in res.risk_level


def test_stego_detection(simulated_stego_image, tmp_path):
    bp_dir = tmp_path / "bitplanes"
    res = StegoInspector.inspect(simulated_stego_image, save_bitplanes_dir=bp_dir)
    assert res.bitplane_entropies is not None
    # LSB entropy should be near 1.0
    r_plane0_ent = res.bitplane_entropies["red"]["plane_0"]["entropy"]
    assert r_plane0_ent > 0.95
    assert res.stego_risk_score >= 0.3
    # Check exported bitplane images
    assert len(res.saved_bitplane_files) > 0
