"""Tests for CLI subcommands."""

import os
import pytest
from click.testing import CliRunner
from PIL import Image
from imgint.cli.main import cli


@pytest.fixture
def sample_jpeg(tmp_path):
    img_path = tmp_path / "test.jpg"
    img = Image.new("RGB", (64, 64), color="blue")
    img.save(img_path, "JPEG", quality=90)
    return str(img_path)


@pytest.fixture
def sample_jpeg_modified(tmp_path, sample_jpeg):
    img_path = tmp_path / "test_mod.jpg"
    img = Image.new("RGB", (64, 64), color="red")
    img.save(img_path, "JPEG", quality=85)
    return str(img_path)


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "matazero" in result.output
    assert "diff" in result.output
    assert "stego" in result.output
    assert "timeline" in result.output


def test_cli_analyze_self_audit(sample_jpeg):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", sample_jpeg, "-a", "-f", "json"])
    assert result.exit_code == 0
    assert "findings" in result.output


def test_cli_diff(sample_jpeg, sample_jpeg_modified):
    runner = CliRunner()
    result = runner.invoke(cli, ["diff", sample_jpeg, sample_jpeg_modified, "-a"])
    assert result.exit_code == 0
    assert "Forensic Verdict" in result.output


def test_cli_diff_json(sample_jpeg, sample_jpeg_modified):
    runner = CliRunner()
    result = runner.invoke(cli, ["diff", sample_jpeg, sample_jpeg_modified, "-a", "-f", "json"])
    assert result.exit_code == 0
    assert "relationship_verdict" in result.output


def test_cli_stego(sample_jpeg):
    runner = CliRunner()
    result = runner.invoke(cli, ["stego", sample_jpeg, "-a"])
    assert result.exit_code == 0
    assert "Stego Verdict" in result.output
    assert "Bitplane" in result.output


def test_cli_stego_json(sample_jpeg):
    runner = CliRunner()
    result = runner.invoke(cli, ["stego", sample_jpeg, "-a", "-f", "json"])
    assert result.exit_code == 0
    assert "stego_risk_score" in result.output


def test_cli_timeline(sample_jpeg, sample_jpeg_modified):
    runner = CliRunner()
    result = runner.invoke(cli, ["timeline", sample_jpeg, sample_jpeg_modified, "-a"])
    assert result.exit_code == 0
    assert "Chronological Evidence Sequence" in result.output


def test_cli_timeline_plaso(sample_jpeg, sample_jpeg_modified):
    runner = CliRunner()
    result = runner.invoke(cli, ["timeline", sample_jpeg, sample_jpeg_modified, "-a", "-f", "plaso"])
    assert result.exit_code == 0
    assert "timestamp_desc" in result.output
