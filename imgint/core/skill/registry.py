"""Skill registry and dynamic discovery engine for matazero."""

from __future__ import annotations
import importlib.util
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Type

from imgint.core.skill.base import ForensicSkill
from imgint.core.skill.manifest import SkillManifest


class SkillRegistry:
    """Discovers, loads, and manages external forensic skills and plugins."""

    _instance: Optional[SkillRegistry] = None

    def __init__(self) -> None:
        self._skills: Dict[str, ForensicSkill] = {}
        self._manifests: Dict[str, SkillManifest] = {}

    @classmethod
    def get_default(cls) -> SkillRegistry:
        if cls._instance is None:
            cls._instance = SkillRegistry()
            cls._instance.discover_skills()
        return cls._instance

    def register_skill(self, skill: ForensicSkill, manifest: Optional[SkillManifest] = None) -> None:
        """Registers an initialized skill instance."""
        self._skills[skill.id] = skill
        if manifest:
            self._manifests[skill.id] = manifest

    def get_skill(self, skill_id: str) -> Optional[ForensicSkill]:
        return self._skills.get(skill_id)

    def list_skills(self) -> List[ForensicSkill]:
        return list(self._skills.values())

    def get_skills_for_tier(self, tier: int, format_name: str = "*") -> List[ForensicSkill]:
        res = []
        for s in self._skills.values():
            if s.target_tier == tier:
                if "*" in s.supported_formats or format_name in s.supported_formats:
                    res.append(s)
        return res

    def discover_skills(self, search_paths: Optional[List[Path]] = None) -> int:
        """Discovers skills across filesystem locations and Python entry points."""
        paths = search_paths or [
            Path("./.matazero/skills").resolve(),
            Path("./skills").resolve(),
            Path.home() / ".matazero" / "skills",
        ]

        count = 0
        for base_path in paths:
            if not base_path.exists() or not base_path.is_dir():
                continue
            for skill_dir in base_path.iterdir():
                if not skill_dir.is_dir():
                    continue
                # Look for manifest
                manifest_file = None
                for mf_name in ("skill.yaml", "skill.yml", "skill.json"):
                    cand = skill_dir / mf_name
                    if cand.exists():
                        manifest_file = cand
                        break

                if manifest_file:
                    try:
                        manifest = SkillManifest.from_file(manifest_file)
                        skill_inst = self._load_skill_from_directory(skill_dir, manifest)
                        if skill_inst:
                            self.register_skill(skill_inst, manifest)
                            count += 1
                    except Exception:
                        pass

        return count

    def _load_skill_from_directory(self, skill_dir: Path, manifest: SkillManifest) -> Optional[ForensicSkill]:
        """Dynamically loads a skill Python module from a directory."""
        entry_parts = manifest.entry_point.split(":")
        rel_file = entry_parts[0]
        class_name = entry_parts[1] if len(entry_parts) > 1 else "CustomSkill"

        py_file = skill_dir / rel_file
        if not py_file.exists():
            return None

        spec = importlib.util.spec_from_file_location(f"matazero_skill_{manifest.id}", py_file)
        if not spec or not spec.loader:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[f"matazero_skill_{manifest.id}"] = module
        spec.loader.exec_module(module)

        skill_cls = getattr(module, class_name, None)
        if skill_cls and issubclass(skill_cls, ForensicSkill):
            return skill_cls()
        return None
