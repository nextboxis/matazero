"""BMP container reader parsing BMP header, DIB header, and pixel array."""

from __future__ import annotations
import struct
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError


class BmpContainerReader(ContainerReader):
    """Parses BMP containers into StructuralUnits and checks for trailing data."""

    def handles(self, format_name: str) -> bool:
        return format_name == "BMP"

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        size = reader.size
        if size < 14:
            diagnostics.append(
                Diagnostic(level="error", message="BMP file too small (< 14 bytes)", source="bmp_reader", offset=0)
            )
            return units, blocks, diagnostics

        sig = reader.read_bytes(0, 2)
        if sig != b"BM":
            diagnostics.append(
                Diagnostic(level="error", message="Invalid BMP magic signature", source="bmp_reader", offset=0)
            )
            return units, blocks, diagnostics

        file_size_hdr = reader.read_u32_le(2)
        pixel_offset = reader.read_u32_le(10)

        units.append(
            StructuralUnit(
                name="BMP_HEADER",
                offset=0,
                length=14,
                data_offset=0,
                data_length=14,
                description=f"BMP File Header (Claimed Size: {file_size_hdr:,} bytes, Pixel Offset: 0x{pixel_offset:X})",
            )
        )

        if size >= 18:
            dib_size = reader.read_u32_le(14)
            dib_len = min(dib_size, size - 14)
            dib_name = "BITMAPINFOHEADER" if dib_size == 40 else f"DIB_HEADER_{dib_size}B"
            units.append(
                StructuralUnit(
                    name="DIB_HEADER",
                    offset=14,
                    length=dib_len,
                    data_offset=14,
                    data_length=dib_len,
                    description=f"{dib_name} ({dib_size} bytes)",
                )
            )

        if 0 < pixel_offset < size:
            pixel_len = min(size - pixel_offset, file_size_hdr - pixel_offset if file_size_hdr > pixel_offset else size - pixel_offset)
            units.append(
                StructuralUnit(
                    name="PIXEL_ARRAY",
                    offset=pixel_offset,
                    length=pixel_len,
                    data_offset=pixel_offset,
                    data_length=pixel_len,
                    description=f"BMP Raster Pixel Array ({pixel_len:,} bytes)",
                )
            )

            end_of_image = max(pixel_offset + pixel_len, file_size_hdr) if file_size_hdr <= size else pixel_offset + pixel_len
            if end_of_image < size:
                trailing_len = size - end_of_image
                units.append(
                    StructuralUnit(
                        name="TRAILING_DATA",
                        offset=end_of_image,
                        length=trailing_len,
                        data_offset=end_of_image,
                        data_length=trailing_len,
                        description=f"Appended trailing bytes ({trailing_len} bytes) after BMP stream",
                        payload=reader.read_bytes(end_of_image, min(trailing_len, 4096)),
                    )
                )

        return units, blocks, diagnostics
