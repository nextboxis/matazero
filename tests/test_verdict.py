"""Tests for Authenticity and Integrity Verdict Evaluator."""

import pytest
from imgint.core.analyzer.verdict import AuthenticityEvaluator, AuthenticityVerdict
from imgint.core.model.record import AnalysisRecord, StructuralUnit, Field
from imgint.core.model.finding import Finding, Confidence, Provenance


def test_verdict_authentic_camera_profile():
    """Test evaluating authentic image with matching camera hardware ISP."""
    record = AnalysisRecord(
        file_path="sample.jpg",
        file_size=2_000_000,
        mime_type="image/jpeg",
        sha256="abc12345",
        tool_version="2.0.0",
        corpus_version="2026.08.2-expanded",
    )
    record.fields.append(Field(standard="EXIF", name="Make", value="Apple", raw_value="Apple", value_type="STRING"))
    record.findings.append(
        Finding(
            name="encoder_attribution",
            value={
                "Device Model": "Apple iPhone Camera (iOS Camera App, iPhone 11-16 Pro)",
                "Encoder Software": "Apple iOS JPEG Hardware Encoder",
                "Similarity Score": 1.0,
            },
            tier=2,
            extractor="fingerprint_matcher",
            confidence=Confidence.INDICATIVE,
            caveat="Caveat text",
            provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
        )
    )
    record.findings.append(
        Finding(
            name="gps_location_fix",
            value={"latitude": 37.7749, "longitude": -122.4194, "nearest_place": "San Francisco"},
            tier=5,
            extractor="geotime_analyzer",
            confidence=Confidence.OBSERVED,
            caveat=None,
            provenance=Provenance(source_layer="analyzer", extractor="geotime_analyzer"),
        )
    )

    verdict = AuthenticityEvaluator.evaluate(record)
    assert verdict.is_authentic is True
    assert verdict.verdict_label == "AUTHENTIC_CAMERA_CAPTURE"
    assert verdict.confidence_score >= 0.90
    assert verdict.risk_level == "LOW"
    assert verdict.integrity_flags["hardware_encoder_match"] is True
    assert verdict.integrity_flags["container_intact"] is True


def test_verdict_tampered_trailing_payload():
    """Test evaluating container with trailing hidden payload."""
    record = AnalysisRecord(
        file_path="suspicious.jpg",
        file_size=500_000,
        mime_type="image/jpeg",
        sha256="def67890",
        tool_version="2.0.0",
        corpus_version="2026.08.2-expanded",
    )
    record.structural_units.append(
        StructuralUnit(name="TRAILING_DATA", offset=400_000, length=100_000, data_offset=400_000, data_length=100_000)
    )
    record.findings.append(
        Finding(
            name="trailing_data_detected",
            value={"detected_payload_type": "ZIP Archive"},
            tier=3,
            extractor="trailing_data_extractor",
            confidence=Confidence.OBSERVED,
            caveat=None,
            provenance=Provenance(source_layer="artefact", extractor="trailing_data_extractor"),
        )
    )

    verdict = AuthenticityEvaluator.evaluate(record)
    assert verdict.is_authentic is False
    assert verdict.verdict_label == "TAMPERED_TRAILING_PAYLOAD"
    assert verdict.risk_level == "CRITICAL"
    assert verdict.integrity_flags["trailing_payload_detected"] is True
    assert verdict.integrity_flags["container_intact"] is False


def test_verdict_ai_generation():
    """Test evaluating image attributed to Generative AI generator."""
    record = AnalysisRecord(
        file_path="midjourney.jpg",
        file_size=1_200_000,
        mime_type="image/jpeg",
        sha256="99988877",
        tool_version="2.0.0",
        corpus_version="2026.08.2-expanded",
    )
    record.findings.append(
        Finding(
            name="encoder_attribution",
            value={
                "Device Model": "Midjourney AI (v5/v6 Discord Export)",
                "Encoder Software": "Midjourney Upscaler / Export Pipeline",
                "Similarity Score": 0.95,
            },
            tier=2,
            extractor="fingerprint_matcher",
            confidence=Confidence.INDICATIVE,
            caveat="Caveat text",
            provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
        )
    )

    verdict = AuthenticityEvaluator.evaluate(record)
    assert verdict.is_authentic is False
    assert verdict.verdict_label == "AI_SYNTHETIC_GENERATION"
    assert verdict.risk_level == "HIGH"
    assert verdict.integrity_flags["ai_generation_detected"] is True


def test_verdict_stripped_social_media():
    """Test evaluating image with stripped metadata."""
    record = AnalysisRecord(
        file_path="web_photo.jpg",
        file_size=40_000,
        mime_type="image/jpeg",
        sha256="11122233",
        tool_version="2.0.0",
        corpus_version="2026.08.2-expanded",
    )
    verdict = AuthenticityEvaluator.evaluate(record)
    assert verdict.is_authentic is None  # Inconclusive
    assert verdict.verdict_label == "UNVERIFIED_METADATA_STRIPPED"
    assert verdict.risk_level == "MEDIUM"
    assert len(verdict.forensic_caveats) > 0
