"""ISO-BMFF (HEIC / AVIF) container reader parsing boxes."""

from __future__ import annotations
import struct
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError


class BmffContainerReader(ContainerReader):
    """Parses ISO-BMFF boxes (HEIC, AVIF) into StructuralUnits."""

    def handles(self, format_name: str) -> bool:
        return format_name in ("HEIC", "AVIF")

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        size = reader.size
        offset = 0

        while offset < size:
            try:
                reader.check_unit_budget()
            except SourceBoundsError as e:
                diagnostics.append(
                    Diagnostic(level="warning", message=str(e), source="bmff_reader", offset=offset)
                )
                break

            if offset + 8 > size:
                break

            box_size = reader.read_u32_be(offset)
            box_type_bytes = reader.read_bytes(offset + 4, 4)
            box_type = box_type_bytes.decode("ascii", errors="replace")

            header_len = 8
            if box_size == 1:
                # 64-bit large size
                if offset + 16 > size:
                    break
                box_size = struct.unpack(">Q", reader.read_bytes(offset + 8, 8))[0]
                header_len = 16
            elif box_size == 0:
                # Extends to EOF
                box_size = size - offset

            if box_size < header_len or offset + box_size > size:
                box_size = size - offset

            if box_size < header_len:
                break

            data_offset = offset + header_len
            data_len = max(0, box_size - header_len)
            payload_bytes = reader.read_bytes(data_offset, min(data_len, 4096)) if data_len > 0 else b""

            units.append(
                StructuralUnit(
                    name=f"BOX_{box_type}",
                    offset=offset,
                    length=box_size,
                    data_offset=data_offset,
                    data_length=data_len,
                    description=f"ISO-BMFF Box '{box_type}' ({box_size} bytes)",
                    payload=payload_bytes,
                )
            )

            # Check for embedded metadata in item data or meta boxes
            if box_type == "Exif":
                raw_exif = payload_bytes
                if raw_exif.startswith(b"Exif\x00\x00"):
                    raw_exif = raw_exif[6:]
                blocks.append(
                    MetadataBlock(
                        kind="EXIF",
                        offset=data_offset,
                        length=data_len,
                        raw_bytes=raw_exif,
                        source_unit="BMFF_Exif",
                    )
                )
            elif box_type == "mime" and b"application/rdf+xml" in payload_bytes:
                blocks.append(
                    MetadataBlock(
                        kind="XMP",
                        offset=data_offset,
                        length=data_len,
                        raw_bytes=payload_bytes,
                        source_unit="BMFF_mime_xmp",
                    )
                )

            advance = max(header_len, box_size)
            offset += advance
            if offset <= 0 or advance <= 0:
                break

        return units, blocks, diagnostics
