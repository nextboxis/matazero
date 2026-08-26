"""Hash manifest generator for evidence packages per SRD FR-9.5."""

from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from imgint.core.model.record import AnalysisRecord


class HashManifestGenerator:
    """Generates cryptographic hash manifests covering all referenced artefacts."""

    @staticmethod
    def generate_manifest(records: List[AnalysisRecord]) -> Dict[str, Any]:
        manifest_items: List[Dict[str, Any]] = []

        for r in records:
            item = {
                "file_path": r.file_path,
                "file_size": r.file_size,
                "file_sha256": r.sha256,
                "data_stream_sha256": r.data_stream_sha256,
                "findings_count": len(r.findings),
            }
            manifest_items.append(item)

        manifest_data = {
            "schema_version": "2.0.0",
            "manifest_type": "imgint_evidence_hash_manifest",
            "items_count": len(manifest_items),
            "files": manifest_items,
        }
        manifest_json_bytes = json.dumps(manifest_data, sort_keys=True).encode("utf-8")
        manifest_data["manifest_sha256"] = hashlib.sha256(manifest_json_bytes).hexdigest()
        return manifest_data
