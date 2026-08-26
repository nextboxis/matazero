"""ICC profile parser and multi-chunk profile counter per SRD FR-2.7."""

from __future__ import annotations
import struct
from typing import Dict, List, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.standard.base import BlockParser


class IccParser(BlockParser):
    """Parses ICC Color Profile headers and tag tables."""

    def handles(self, kind: str) -> bool:
        return kind in ("ICC", "ICC_PROFILE")

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        data = block.raw_bytes
        # In JPEG APP2, ICC profiles have a 2-byte chunk sequence prefix e.g. [chunk_no, total_chunks]
        if block.source_unit == "APP2_ICC" and len(data) >= 2:
            data = data[2:]
        elif len(data) >= 2 and data[0] == 1 and data[1] >= 1:
            data = data[2:]

        size = len(data)
        if size < 128:
            diagnostics.append(
                Diagnostic(level="warning", message="ICC Profile header too short (< 128 bytes)", source="icc_parser", offset=block.offset)
            )
            return fields, findings, diagnostics

        profile_size = struct.unpack(">I", data[0:4])[0]
        cmm_type = data[4:8].decode("ascii", errors="replace").strip()
        version_major = data[8]
        version_minor = (data[9] >> 4)
        profile_class = data[12:16].decode("ascii", errors="replace").strip()
        color_space = data[16:20].decode("ascii", errors="replace").strip()
        connection_space = data[20:24].decode("ascii", errors="replace").strip()
        signature = data[36:40].decode("ascii", errors="replace").strip()
        platform = data[40:44].decode("ascii", errors="replace").strip()
        device_mfg = data[48:52].decode("ascii", errors="replace").strip()
        device_model = data[52:56].decode("ascii", errors="replace").strip()

        fields.append(Field(standard="ICC", name="ProfileSize", value=profile_size, raw_value=profile_size, value_type="INT", offset=block.offset, value_offset=block.offset, length=4))
        fields.append(Field(standard="ICC", name="Version", value=f"{version_major}.{version_minor}", raw_value=data[8:12].hex(), value_type="STRING", offset=block.offset, value_offset=block.offset + 8, length=4))
        fields.append(Field(standard="ICC", name="DeviceClass", value=profile_class, raw_value=profile_class, value_type="STRING", offset=block.offset, value_offset=block.offset + 12, length=4))
        fields.append(Field(standard="ICC", name="ColorSpace", value=color_space, raw_value=color_space, value_type="STRING", offset=block.offset, value_offset=block.offset + 16, length=4))
        fields.append(Field(standard="ICC", name="ConnectionSpace", value=connection_space, raw_value=connection_space, value_type="STRING", offset=block.offset, value_offset=block.offset + 20, length=4))
        fields.append(Field(standard="ICC", name="DeviceManufacturer", value=device_mfg, raw_value=device_mfg, value_type="STRING", offset=block.offset, value_offset=block.offset + 48, length=4))
        fields.append(Field(standard="ICC", name="DeviceModel", value=device_model, raw_value=device_model, value_type="STRING", offset=block.offset, value_offset=block.offset + 52, length=4))

        findings.append(
            Finding(
                name="icc_profile_header",
                value={
                    "version": f"{version_major}.{version_minor}",
                    "device_class": profile_class,
                    "color_space": color_space,
                    "device_manufacturer": device_mfg,
                    "device_model": device_model,
                    "profile_size_bytes": profile_size,
                },
                tier=1,
                extractor="icc_parser",
                confidence=Confidence.OBSERVED,
                caveat=None,
                provenance=Provenance(
                    source_layer="standard",
                    extractor="icc_parser",
                    offset=block.offset,
                    length=min(profile_size, size),
                    standard="ICC",
                ),
            )
        )

        return fields, findings, diagnostics
