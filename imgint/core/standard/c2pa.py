"""C2PA / JUMBF manifest and assertion parser per SRD FR-2.11."""

from __future__ import annotations
import re
from typing import Dict, List, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.standard.base import BlockParser


class C2paParser(BlockParser):
    """Detects and parses C2PA / JUMBF authenticity manifest blocks and action assertions."""

    def handles(self, kind: str) -> bool:
        return kind in ("C2PA", "JUMBF")

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        data = block.raw_bytes
        has_jumbf = b"jumb" in data or b"c2pa" in data
        claim_generator = "Unknown"
        actions_found: List[str] = []

        # Extract claim generator if present
        if b"claim_generator" in data:
            idx = data.find(b"claim_generator")
            claim_bytes = data[idx : idx + 200]
            text = claim_bytes.decode("utf-8", errors="ignore")
            # Match "claim_generator": "Adobe Photoshop 2024" or claim_generator="Tool"
            m = re.search(r'claim_generator["\s:]+([^"\r\n,}]+)', text)
            if m:
                claim_generator = m.group(1).strip().strip('"')
            else:
                claim_generator = "C2PA_Manifest"

        # Search for standard C2PA action assertions
        known_actions = [
            b"c2pa.created",
            b"c2pa.cropped",
            b"c2pa.filtered",
            b"c2pa.color_adjustments",
            b"c2pa.resized",
            b"c2pa.placed",
            b"c2pa.transcoded",
            b"c2pa.edited",
        ]
        for act in known_actions:
            if act in data:
                actions_found.append(act.decode("ascii"))

        # Look for signature info / signing authority strings
        signer_info = "Self-contained assertion"
        if b"CN=" in data or b"OU=" in data:
            signer_info = "X.509 Certificate Chain Present"

        fields.append(
            Field(
                standard="C2PA",
                name="ManifestPresent",
                value=has_jumbf,
                raw_value=has_jumbf,
                value_type="BOOL",
                offset=block.offset,
                value_offset=block.offset,
                length=block.length,
            )
        )
        if actions_found:
            fields.append(
                Field(
                    standard="C2PA",
                    name="DeclaredActions",
                    value=", ".join(actions_found),
                    raw_value=actions_found,
                    value_type="STRING",
                    offset=block.offset,
                    value_offset=block.offset,
                    length=block.length,
                )
            )

        findings.append(
            Finding(
                name="c2pa_manifest_presence",
                value={
                    "present": True,
                    "box_type": "jumb",
                    "claim_generator": claim_generator,
                    "actions_history": actions_found,
                    "signature_status": signer_info,
                    "byte_length": len(data),
                },
                tier=1,
                extractor="c2pa_parser",
                confidence=Confidence.OBSERVED,
                caveat="C2PA assertions record claims by the signing tool; cryptographic trust depends on valid root certificates.",
                provenance=Provenance(
                    source_layer="standard",
                    extractor="c2pa_parser",
                    offset=block.offset,
                    length=block.length,
                    standard="C2PA",
                ),
            )
        )

        return fields, findings, diagnostics
