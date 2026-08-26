"""Tests for Hashing, Geotime, Indicators, Sandbox, Clean, and CLI."""

import pytest
import subprocess
import sys
import json
from pathlib import Path
from click.testing import CliRunner
from imgint.cli.main import cli
from imgint.core.sandbox.process import SandboxRunner
from imgint.core.clean.cleaner import MetadataCleaner
from imgint.core.model.finding import Finding, Confidence
from imgint.core.governance.scope import AuthorizationScope


def test_sandbox_worker_execution(sample_jpeg):
    res = SandboxRunner.run_decode_tasks(sample_jpeg, tasks=["dimensions", "phashes", "dominant_colors", "entropy"])
    assert res["success"] is True
    tasks = res["tasks"]
    assert "dimensions" in tasks
    assert tasks["dimensions"]["width"] > 0
    assert "phashes" in tasks
    assert "dominant_colors" in tasks


def test_metadata_cleaner_preserves_image_stream(sample_jpeg, temp_dir):
    cleaned_path = temp_dir / "cleaned.jpg"
    cleaned_bytes, orig_len, clean_len = MetadataCleaner.clean_file(sample_jpeg, output_path=cleaned_path)
    assert cleaned_path.exists()
    assert clean_len > 0
    assert cleaned_bytes.startswith(b"\xFF\xD8")
    assert cleaned_bytes.endswith(b"\xFF\xD9")


def test_finding_requires_caveat_for_derived_and_indicative():
    # OBSERVED does not require caveat
    f_obs = Finding(
        name="test_obs",
        value=123,
        tier=1,
        extractor="test",
        confidence=Confidence.OBSERVED,
    )
    assert f_obs.confidence == Confidence.OBSERVED

    # DERIVED requires caveat per ADR-008
    with pytest.raises(ValueError) as exc:
        Finding(
            name="test_derived_no_caveat",
            value=123,
            tier=5,
            extractor="test",
            confidence=Confidence.DERIVED,
            caveat="",
        )
    assert "caveat" in str(exc.value).lower()


def test_cli_help_and_version():
    runner = CliRunner()
    res = runner.invoke(cli, ["--version"])
    assert res.exit_code == 0
    assert "matazero" in res.output or "imgint" in res.output

    res_help = runner.invoke(cli, ["--help"])
    assert res_help.exit_code == 0
    assert "scope" in res_help.output
    assert "analyze" in res_help.output
    assert "probe" in res_help.output
    assert "audit" in res_help.output
    assert "clean" in res_help.output


def test_cli_analyze_self_audit(sample_jpeg):
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", str(sample_jpeg), "--self-audit", "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "findings" in data
    assert data["mime_type"] == "image/jpeg"
    assert "not_established" in data


def test_cli_probe(sample_jpeg):
    runner = CliRunner()
    res = runner.invoke(cli, ["probe", str(sample_jpeg)])
    assert res.exit_code == 0
    assert "Structural Units" in res.output
    assert "SOI" in res.output
