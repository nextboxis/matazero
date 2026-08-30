"""Tests for Microkernel Skill / Plugin System."""

import pytest
from pathlib import Path
from imgint.core.skill import ForensicSkill, SkillManifest, SkillRegistry
from imgint.core.analyzer.base import AnalysisContext
from imgint.core.model.finding import Finding, Confidence
from imgint.core.model.record import Diagnostic


class MockDroneSkill(ForensicSkill):
    @property
    def id(self) -> str:
        return "mock_drone_telemetry"

    @property
    def name(self) -> str:
        return "Mock Drone Telemetry Skill"

    @property
    def target_tier(self) -> int:
        return 5

    def analyze(self, ctx: AnalysisContext):
        f = Finding(
            name="mock_drone_altitude",
            value={"altitude_rel_meters": 120.5},
            tier=5,
            extractor=self.id,
            confidence=Confidence.OBSERVED,
        )
        return [f], []


def test_skill_registration():
    reg = SkillRegistry()
    skill = MockDroneSkill()
    reg.register_skill(skill)

    assert reg.get_skill("mock_drone_telemetry") is not None
    assert len(reg.list_skills()) == 1

    tier5_skills = reg.get_skills_for_tier(5)
    assert len(tier5_skills) == 1
    assert tier5_skills[0].id == "mock_drone_telemetry"


def test_skill_manifest_loading(tmp_path):
    manifest_file = tmp_path / "skill.json"
    manifest_file.write_text("""
    {
        "id": "cctv_scanner",
        "name": "CCTV Parser Skill",
        "version": "2.1.0",
        "target_tier": 6,
        "supported_formats": ["JPEG", "TIFF"]
    }
    """, encoding="utf-8")

    manifest = SkillManifest.from_file(manifest_file)
    assert manifest.id == "cctv_scanner"
    assert manifest.version == "2.1.0"
    assert manifest.target_tier == 6
    assert "JPEG" in manifest.supported_formats
