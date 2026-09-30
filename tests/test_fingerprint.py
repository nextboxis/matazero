"""Tests for DQT extraction, quantization tables, and reference corpus matching."""

from imgint.core.fingerprint.dqt import DqtExtractor, IJG_LUMINANCE_BASE
from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.fingerprint.composite import EncoderFingerprint
from imgint.core.fingerprint.matcher import FingerprintMatcher
from imgint.core.model.finding import Confidence


def test_dqt_extractor_parsing():
    payload = b"\x00" + bytes(IJG_LUMINANCE_BASE)
    tables = DqtExtractor.extract_from_dqt_payload(payload)

    assert len(tables) == 1
    table = tables[0]
    assert table.table_id == 0
    assert table.precision == 0
    assert table.values == IJG_LUMINANCE_BASE
    assert table.table_type == "Luminance"
    assert table.estimated_quality is not None
    assert 40 <= table.estimated_quality <= 60


def test_reference_corpus_seed_loading():
    corpus = ReferenceCorpus()
    assert len(corpus.entries) > 0

    models = [e.device_model for e in corpus.entries]
    assert any("iPhone" in m for m in models)
    assert any("Galaxy" in m for m in models)
    assert any("Pixel" in m for m in models)


def test_fingerprint_matcher_insufficient_data():
    corpus = ReferenceCorpus()
    empty_fp = EncoderFingerprint(format_name="JPEG")
    finding = FingerprintMatcher.match(empty_fp, corpus)

    assert finding.name == "encoder_attribution"
    assert finding.confidence == Confidence.INCONCLUSIVE
    assert "insufficient" in str(finding.value).lower()
