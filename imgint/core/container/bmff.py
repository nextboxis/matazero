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
                if offset + 16 > size:
                    break
                box_size = struct.unpack(">Q", reader.read_bytes(offset + 8, 8))[0]
                header_len = 16
            elif box_size == 0:
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

            if box_type == "Exif":
                full_len = min(data_len, reader.max_read_size)
                raw_exif = reader.read_bytes(data_offset, full_len) if full_len > 0 else b""
                exif_sig_idx = raw_exif.find(b"Exif\x00\x00", 0, 16)
                if exif_sig_idx != -1:
                    raw_exif = raw_exif[exif_sig_idx + 6 :]
                blocks.append(
                    MetadataBlock(
                        kind="EXIF",
                        offset=data_offset,
                        length=len(raw_exif),
                        raw_bytes=raw_exif,
                        source_unit="BMFF_Exif",
                    )
                )
            elif box_type == "mime" and b"application/rdf+xml" in payload_bytes:
                full_len = min(data_len, reader.max_read_size)
                raw_xmp = reader.read_bytes(data_offset, full_len) if full_len > 0 else b""
                blocks.append(
                    MetadataBlock(
                        kind="XMP",
                        offset=data_offset,
                        length=len(raw_xmp),
                        raw_bytes=raw_xmp,
                        source_unit="BMFF_mime_xmp",
                    )
                )

            advance = max(header_len, box_size)
            offset += advance
            if offset <= 0 or advance <= 0:
                break

        return units, blocks, diagnostics
