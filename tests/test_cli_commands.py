from pathlib import Path
from click.testing import CliRunner
import pytest

from imgint.cli.main import cli


@pytest.fixture
def sample_jpeg(tmp_path: Path) -> Path:
    img = tmp_path / "sample.jpg"
    img.write_bytes(
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
        b"\xff\xdb\x00C\x00" + b"\x10" * 64 +
        b"\xff\xc0\x00\x0b\x08\x00\x10\x00\x10\x01\x01\x11\x00"
        b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00"
        b"\xff\xd9"
    )
    return img


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "matazero" in result.output


def test_cli_doctor():
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0


def test_cli_analyze_self_audit(sample_jpeg: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(sample_jpeg), "-a"])
    assert result.exit_code == 0
    assert "matazero" in result.output or "Evidence" in result.output


def test_cli_default_group_analyze(sample_jpeg: Path):
    runner = CliRunner()
    result = runner.invoke(cli, [str(sample_jpeg), "-a"])
    assert result.exit_code == 0


def test_cli_locate(sample_jpeg: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["locate", str(sample_jpeg)])
    assert result.exit_code == 0


def test_cli_scope_create_and_validate(tmp_path: Path):
    scope_file = tmp_path / "scope.json"
    runner = CliRunner()
    res1 = runner.invoke(cli, [
        "scope", "create",
        "-c", "CASE-TEST-001",
        "-p", "test-investigation",
        "-l", "Consent",
        "-a", "Analyst",
        "-o", str(scope_file),
    ])
    assert res1.exit_code == 0
    assert scope_file.exists()

    res2 = runner.invoke(cli, ["scope", "validate", str(scope_file)])
    assert res2.exit_code == 0


def test_cli_clean(sample_jpeg: Path, tmp_path: Path):
    out_file = tmp_path / "cleaned.jpg"
    runner = CliRunner()
    result = runner.invoke(cli, ["clean", str(sample_jpeg), "-o", str(out_file), "-c"])
    assert result.exit_code == 0
    assert out_file.exists()
