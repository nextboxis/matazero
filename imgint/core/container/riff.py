"""RIFF / WebP container reader."""

from __future__ import annotations
import struct
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError


class RiffContainerReader(ContainerReader):
    """Parses RIFF/WebP chunks into StructuralUnits and MetadataBlocks."""

    def handles(self, format_name: str) -> bool:
        return format_name == "WEBP"

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        size = reader.size
        if size < 12:
            diagnostics.append(
                Diagnostic(level="error", message="RIFF file too small (< 12 bytes)", source="riff_reader", offset=0)
            )
            return units, blocks, diagnostics

        header = reader.read_bytes(0, 12)
        if header[:4] != b"RIFF" or header[8:12] != b"WEBP":
            diagnostics.append(
                Diagnostic(level="error", message="Not a valid RIFF/WEBP container", source="riff_reader", offset=0)
            )
            return units, blocks, diagnostics

        units.append(
            StructuralUnit(
                name="RIFF_HEADER",
                offset=0,
                length=12,
                data_offset=0,
                data_length=12,
                description="RIFF/WEBP Header",
            )
        )

        offset = 12
        while offset < size:
            try:
                reader.check_unit_budget()
            except SourceBoundsError as e:
                diagnostics.append(
                    Diagnostic(level="warning", message=str(e), source="riff_reader", offset=offset)
                )
                break

            if offset + 8 > size:
                break

            fourcc_bytes = reader.read_bytes(offset, 4)
            fourcc = fourcc_bytes.decode("ascii", errors="replace")
            chunk_size = reader.read_u32_le(offset + 4)
            padded_size = (chunk_size + 1) & ~1
            total_len = 8 + padded_size

            data_offset = offset + 8
            data_len = min(chunk_size, size - data_offset) if data_offset <= size else 0

            payload_bytes = reader.read_bytes(data_offset, data_len)

            units.append(
                StructuralUnit(
                    name=f"RIFF_{fourcc.strip()}",
                    offset=offset,
                    length=min(total_len, size - offset),
                    data_offset=data_offset,
                    data_length=data_len,
                    description=f"WebP Chunk {fourcc}",
                    payload=payload_bytes,
                )
            )

            if fourcc.strip() == "EXIF":
                # WebP EXIF chunk
                raw_exif = payload_bytes
                if raw_exif.startswith(b"Exif\x00\x00"):
                    raw_exif = raw_exif[6:]
                blocks.append(
                    MetadataBlock(
                        kind="EXIF",
                        offset=data_offset,
                        length=data_len,
                        raw_bytes=raw_exif,
                        source_unit="WEBP_EXIF",
                    )
                )
            elif fourcc.strip() == "XMP":
                blocks.append(
                    MetadataBlock(
                        kind="XMP",
                        offset=data_offset,
                        length=data_len,
                        raw_bytes=payload_bytes,
                        source_unit="WEBP_XMP",
                    )
                )
            elif fourcc.strip() == "ICCP":
                blocks.append(
                    MetadataBlock(
                        kind="ICC",
                        offset=data_offset,
                        length=data_len,
                        raw_bytes=payload_bytes,
                        source_unit="WEBP_ICCP",
                    )
                )

            offset += total_len

        return units, blocks, diagnostics
