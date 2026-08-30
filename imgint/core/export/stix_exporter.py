"""STIX 2.1 Threat Intelligence bundle generator for evidence indicators."""

from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from imgint.core.model.record import AnalysisRecord


class StixExporter:
    """Exports forensic analysis records into standard STIX 2.1 Threat Intelligence Bundles."""

    @classmethod
    def export(cls, records: List[AnalysisRecord]) -> Dict[str, Any]:
        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: List[Dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for rec in records:
            file_id = f"file--{uuid.uuid4()}"
            file_name = Path(rec.file_path).name

            # 1. File SCO
            file_sco = {
                "type": "file",
                "spec_version": "2.1",
                "id": file_id,
                "name": file_name,
                "hashes": {
                    "SHA-256": rec.sha256,
                },
                "mime_type": rec.mime_type,
            }
            objects.append(file_sco)

            # 2. Check for high risk indicators (Trailing payloads, Stego, Synthetic)
            verdict_f = next((f.value for f in rec.findings if f.name == "authenticity_verdict" and isinstance(f.value, dict)), {})
            risk = verdict_f.get("risk_level", "LOW")
            reasons = verdict_f.get("supporting_reasons", [])

            if risk in ("HIGH", "CRITICAL") or any(f.name == "trailing_data_detected" for f in rec.findings):
                indicator_id = f"indicator--{uuid.uuid4()}"
                desc = f"Forensic image intelligence indicator for {file_name}: {'; '.join(reasons) if reasons else 'High-risk anomaly'}"
                
                indicator_sdo = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Forensic Anomaly: {file_name}",
                    "description": desc,
                    "indicator_types": ["anomalous-activity", "malicious-activity"],
                    "pattern": f"[file:hashes.'SHA-256' = '{rec.sha256}']",
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                }
                objects.append(indicator_sdo)

                # Relationship SDO
                rel_sdo = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": file_id,
                }
                objects.append(rel_sdo)

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }
