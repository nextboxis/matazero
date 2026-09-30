"""End-to-end integration tests for AnalysisPipeline orchestration and lifecycle."""

from pathlib import Path
import pytest

from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.event import ForensicEventBus, AnalysisStartedEvent, AnalysisCompletedEvent


def test_pipeline_execution_sample_image():
    repo_root = Path(__file__).parent.parent
    sample_path = repo_root / "IMG20260829082025.jpg"

    if not sample_path.exists():
        pytest.skip(f"Sample image {sample_path} not found")

    scope = AuthorizationScope.create_self_audit_scope()
    pipeline = AnalysisPipeline(scope=scope, allow_network=False)

    events_captured = []

    def _on_start(ev):
        events_captured.append(("start", ev.file_path))

    def _on_complete(ev):
        events_captured.append(("complete", ev.sha256))

    bus = ForensicEventBus.get_default()
    bus.subscribe(AnalysisStartedEvent, _on_start)
    bus.subscribe(AnalysisCompletedEvent, _on_complete)

    record = pipeline.analyze_file(sample_path)

    assert record.file_path == str(sample_path.resolve())
    assert record.file_size > 0
    assert record.mime_type == "image/jpeg"
    assert len(record.sha256) == 64
    assert len(record.not_established) >= 3

    tier2_findings = record.get_findings_by_tier(2)
    assert len(tier2_findings) > 0, "Pipeline must extract Tier 2 encoder fingerprints"

    assert record.authenticity_verdict is not None
    assert "verdict_label" in record.authenticity_verdict
    assert isinstance(record.authenticity_verdict.get("corroborating_signals"), list)
    assert isinstance(record.authenticity_verdict.get("contradicting_signals"), list)
    assert isinstance(record.authenticity_verdict.get("inconclusive_signals"), list)
    assert len(record.authenticity_verdict.get("corroborating_signals")) > 0

    assert any(e[0] == "start" for e in events_captured)
    assert any(e[0] == "complete" for e in events_captured)


def test_pipeline_missing_file_raises():
    scope = AuthorizationScope.create_self_audit_scope()
    pipeline = AnalysisPipeline(scope=scope)

    with pytest.raises(FileNotFoundError):
        pipeline.analyze_file("non_existent_image_12345.xyz")


def test_pipeline_reader_closed_no_winerror32_on_unlink(tmp_path):
    """Verifies that BoundedReader is cleanly closed, preventing Windows WinError 32 file locks."""
    import shutil
    repo_root = Path(__file__).parent.parent
    sample_path = repo_root / "IMG20260829082025.jpg"

    if not sample_path.exists():
        pytest.skip(f"Sample image {sample_path} not found")

    temp_copy = tmp_path / "temp_evidence.jpg"
    shutil.copy2(sample_path, temp_copy)

    scope = AuthorizationScope.create_self_audit_scope()
    pipeline = AnalysisPipeline(scope=scope, allow_network=False)
    record = pipeline.analyze_file(temp_copy)
    assert record is not None

    temp_copy.unlink()
    assert not temp_copy.exists(), "Working copy should be cleanly deletable immediately after pipeline analysis"
