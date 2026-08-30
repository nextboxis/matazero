"""Manifest parser for skill metadata declarations."""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SkillManifest:
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    target_tier: int = 6
    supported_formats: List[str] = field(default_factory=lambda: ["*"])
    entry_point: str = "skill.py:CustomSkill"
    author: Optional[str] = None
    license: Optional[str] = None
    requires_network: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_file(cls, manifest_path: str | Path) -> SkillManifest:
        p = Path(manifest_path)
        content = p.read_text(encoding="utf-8")
        if p.suffix.lower() == ".json":
            data = json.loads(content)
        else:
            # Basic YAML-like parser without hard yaml dependency
            data = {}
            for line in content.splitlines():
                if ":" in line and not line.strip().startswith("#"):
                    k, v = line.split(":", 1)
                    k = k.strip()
                    v = v.strip().strip('"\'')
                    if v.startswith("[") and v.endswith("]"):
                        v = [item.strip().strip('"\'') for item in v[1:-1].split(",") if item.strip()]
                    elif v.isdigit():
                        v = int(v)
                    elif v.lower() in ("true", "false"):
                        v = v.lower() == "true"
                    data[k] = v

        return cls(
            id=data.get("id") or data.get("name", p.parent.name),
            name=data.get("name", p.parent.name),
            version=str(data.get("version", "1.0.0")),
            description=data.get("description", ""),
            target_tier=int(data.get("target_tier", 6)),
            supported_formats=data.get("supported_formats", ["*"]),
            entry_point=data.get("entry_point", "skill.py:CustomSkill"),
            author=data.get("author"),
            license=data.get("license"),
            requires_network=bool(data.get("requires_network", False)),
        )
