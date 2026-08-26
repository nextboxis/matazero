"""PNG container reader parsing chunks, text, exif, icc, and trailing data."""

from __future__ import annotations
import struct
import zlib
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PngContainerReader(ContainerReader):
    """Parses PNG chunks into StructuralUnits and MetadataBlocks."""

    def handles(self, format_name: str) -> bool:
        return format_name == "PNG"

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        size = reader.size
        if size < 8 or reader.read_bytes(0, 8) != PNG_SIGNATURE:
            diagnostics.append(
                Diagnostic(level="error", message="Missing or invalid PNG signature", source="png_reader", offset=0)
            )
            return units, blocks, diagnostics

        units.append(
            StructuralUnit(
                name="PNG_HEADER",
                offset=0,
                length=8,
                data_offset=0,
                data_length=8,
                description="PNG Signature",
            )
        )

        offset = 8
        iend_seen = False

        while offset < size:
            try:
                reader.check_unit_budget()
            except SourceBoundsError as e:
                diagnostics.append(
                    Diagnostic(level="warning", message=str(e), source="png_reader", offset=offset)
                )
                break

            if offset + 8 > size:
                diagnostics.append(
                    Diagnostic(level="warning", message=f"Truncated chunk header at offset {offset}", source="png_reader", offset=offset)
                )
                break

            data_length = reader.read_u32_be(offset)
            chunk_type_bytes = reader.read_bytes(offset + 4, 4)
            try:
                chunk_type = chunk_type_bytes.decode("ascii", errors="replace")
            except Exception:
                chunk_type = f"CHUNK_{chunk_type_bytes.hex()}"

            total_chunk_length = 12 + data_length
            data_offset = offset + 8

            if data_offset + data_length + 4 > size:
                diagnostics.append(
                    Diagnostic(
                        level="warning",
                        message=f"Chunk {chunk_type} overflows file bounds at offset {offset}",
                        source="png_reader",
                        offset=offset,
                    )
                )
                data_length = max(0, size - data_offset - 4)

            payload_bytes = reader.read_bytes(data_offset, data_length)

            unit = StructuralUnit(
                name=chunk_type,
                offset=offset,
                length=total_chunk_length,
                data_offset=data_offset,
                data_length=data_length,
                description=f"PNG Chunk {chunk_type}",
                payload=payload_bytes,
            )
            units.append(unit)

            # Metadata blocks in PNG
            if chunk_type == "eXIf":
                blocks.append(
                    MetadataBlock(
                        kind="EXIF",
                        offset=data_offset,
                        length=data_length,
                        raw_bytes=payload_bytes,
                        source_unit="PNG_eXIf",
                    )
                )
            elif chunk_type in ("tEXt", "zTXt", "iTXt"):
                blocks.append(
                    MetadataBlock(
                        kind="PNG_TEXT",
                        offset=data_offset,
                        length=data_length,
                        raw_bytes=payload_bytes,
                        source_unit=f"PNG_{chunk_type}",
                    )
                )
            elif chunk_type == "iCCP":
                blocks.append(
                    MetadataBlock(
                        kind="ICC",
                        offset=data_offset,
                        length=data_length,
                        raw_bytes=payload_bytes,
                        source_unit="PNG_iCCP",
                    )
                )
            elif chunk_type in ("tIME", "pHYs", "cHRM", "gAMA", "sRGB"):
                blocks.append(
                    MetadataBlock(
                        kind="PNG_NATIVE",
                        offset=data_offset,
                        length=data_length,
                        raw_bytes=payload_bytes,
                        source_unit=f"PNG_{chunk_type}",
                    )
                )

            offset += total_chunk_length

            if chunk_type == "IEND":
                iend_seen = True
                # Check for trailing data after IEND chunk
                if offset < size:
                    trailing_len = size - offset
                    units.append(
                        StructuralUnit(
                            name="TRAILING_DATA",
                            offset=offset,
                            length=trailing_len,
                            data_offset=offset,
                            data_length=trailing_len,
                            description=f"Appended trailing bytes ({trailing_len} bytes) after IEND",
                            payload=reader.read_bytes(offset, min(trailing_len, 4096)),
                        )
                    )
                break

        return units, blocks, diagnostics
