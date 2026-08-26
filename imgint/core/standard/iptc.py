"""IPTC-IIM parser for Photoshop 8BIM resource blocks per SRD FR-2.6."""

from __future__ import annotations
import struct
from typing import Dict, List, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.standard.base import BlockParser

IPTC_TAGS = {
    (2, 5): "ObjectName (Title)",
    (2, 25): "Keywords",
    (2, 55): "DateCreated",
    (2, 60): "TimeCreated",
    (2, 80): "Byline (Author)",
    (2, 85): "BylineTitle",
    (2, 90): "City",
    (2, 95): "Province/State",
    (2, 101): "CountryName",
    (2, 105): "Headline",
    (2, 110): "Credit",
    (2, 115): "Source",
    (2, 116): "CopyrightNotice",
    (2, 120): "Caption/Abstract",
}


class IptcParser(BlockParser):
    """Parses IPTC-IIM records embedded in 8BIM Photoshop segments."""

    def handles(self, kind: str) -> bool:
        return kind in ("IPTC_8BIM", "IPTC")

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        data = block.raw_bytes
        size = len(data)
        offset = 0

        # Scan for 8BIM blocks
        while offset + 12 <= size:
            # 8BIM signature
            sig = data[offset : offset + 4]
            if sig != b"8BIM":
                offset += 1
                continue

            resource_id = struct.unpack(">H", data[offset + 4 : offset + 6])[0]
            # Resource name is a Pascal string (length byte + padded to even)
            name_len = data[offset + 6]
            name_total_len = (1 + name_len + 1) & ~1
            res_data_offset = offset + 6 + name_total_len

            if res_data_offset + 4 > size:
                break

            res_size = struct.unpack(">I", data[res_data_offset : res_data_offset + 4])[0]
            res_payload_offset = res_data_offset + 4
            res_padded_size = (res_size + 1) & ~1

            if res_payload_offset + res_size > size:
                res_size = size - res_payload_offset

            res_data = data[res_payload_offset : res_payload_offset + res_size]

            # Resource ID 0x0404 is IPTC-NAA record
            if resource_id == 0x0404:
                self._parse_iptc_records(res_data, block.offset + res_payload_offset, fields, findings)

            offset = res_payload_offset + res_padded_size

        return fields, findings, diagnostics

    def _parse_iptc_records(
        self,
        data: bytes,
        base_offset: int,
        fields: List[Field],
        findings: List[Finding],
    ) -> None:
        size = len(data)
        curr = 0

        while curr + 5 <= size:
            tag_marker = data[curr]
            if tag_marker != 0x1C:  # IPTC tag marker
                curr += 1
                continue

            record_num = data[curr + 1]
            dataset_num = data[curr + 2]
            record_len = struct.unpack(">H", data[curr + 3 : curr + 5])[0]
            val_offset = curr + 5

            if val_offset + record_len > size:
                record_len = size - val_offset

            val_bytes = data[val_offset : val_offset + record_len]
            val_str = val_bytes.decode("utf-8", errors="replace").strip()

            tag_key = (record_num, dataset_num)
            tag_name = IPTC_TAGS.get(tag_key, f"Dataset_{record_num}:{dataset_num}")

            fields.append(
                Field(
                    standard="IPTC",
                    tag_id=f"{record_num}:{dataset_num}",
                    name=f"iptc:{tag_name}",
                    value=val_str,
                    raw_value=val_bytes.hex(),
                    value_type="STRING",
                )
            )

            findings.append(
                Finding(
                    name=f"iptc_{tag_name.lower().split()[0].replace('/', '_')}",
                    value=val_str,
                    tier=1,
                    extractor="iptc_parser",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(
                        source_layer="standard",
                        extractor="iptc_parser",
                        offset=base_offset + curr,
                        length=5 + record_len,
                        standard="IPTC",
                        tag_id=f"{record_num}:{dataset_num}",
                    ),
                )
            )

            curr = val_offset + record_len
