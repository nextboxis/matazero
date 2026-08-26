"""Tests for Fingerprint Engine per SRD FR-3.x."""

import pytest
from imgint.core.fingerprint.dqt import DqtExtractor
from imgint.core.fingerprint.subsampling import SubsamplingExtractor
from imgint.core.fingerprint.composite import CompositeFingerprintBuilder
from imgint.core.fingerprint.corpus import ReferenceCorpus
from imgint.core.fingerprint.matcher import FingerprintMatcher
from imgint.core.model.finding import Confidence


def test_dqt_extraction_and_quality_estimation():
    # Build synthetic 8-bit luminance table payload (table 0, 64 bytes of values)
    table_vals = [2, 1, 1, 2, 2, 4, 5, 6] * 8
    payload = bytes([0x00]) + bytes(table_vals)

    tables = DqtExtractor.extract_from_dqt_payload(payload)
    assert len(tables) == 1
    assert tables[0].table_id == 0
    assert tables[0].table_type == "Luminance"
    assert tables[0].estimated_quality is not None
    assert tables[0].estimated_quality > 80


def test_subsampling_extraction():
    # Synthetic SOF0 payload: precision(1), height(2), width(2), components(3), C1(1, 0x22), C2(2, 0x11), C3(3, 0x11)
    sof_payload = bytes([8, 0, 100, 0, 100, 3, 1, 0x22, 1, 2, 0x11, 2, 3, 0x11, 3])
    info = SubsamplingExtractor.extract_from_sof_payload(sof_payload)
    assert info is not None
    assert info.notation == "4:2:0"
    assert info.components_count == 3


def test_fingerprint_matching_and_threshold_fallback():
    corpus = ReferenceCorpus()
    assert len(corpus.entries) > 0

    # Test match with known table
    entry = corpus.entries[0]
    payload = bytes([0x00]) + bytes(entry.dqt_luminance_sample)
    tables = DqtExtractor.extract_from_dqt_payload(payload)

    fp = CompositeFingerprintBuilder.build(
        format_name="JPEG",
        dqt_tables=tables,
        dht_tables=[],
        subsampling=None,
        segment_sequence=["SOI", "APP1", "DQT", "SOF0"],
    )

    finding = FingerprintMatcher.match(fp, corpus)
    assert finding.name == "encoder_attribution"
    assert finding.confidence in (Confidence.INDICATIVE, Confidence.INCONCLUSIVE)
    if finding.confidence == Confidence.INDICATIVE:
        assert "device_model" in finding.value
        assert finding.value["similarity_score"] >= 0.75
