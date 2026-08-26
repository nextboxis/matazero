"""TIFF container reader supporting Little-Endian and Big-Endian IFD directory walks."""

from __future__ import annotations
import struct
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError


class TiffContainerReader(ContainerReader):
    """Parses TIFF containers into StructuralUnits and MetadataBlocks."""

    def handles(self, format_name: str) -> bool:
        return format_name == "TIFF"

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        size = reader.size
        if size < 8:
            diagnostics.append(
                Diagnostic(level="error", message="TIFF file too small (< 8 bytes)", source="tiff_reader", offset=0)
            )
            return units, blocks, diagnostics

        endian_bytes = reader.read_bytes(0, 2)
        if endian_bytes == b"II":
            endian = "<"
            endian_name = "Little-Endian"
        elif endian_bytes == b"MM":
            endian = ">"
            endian_name = "Big-Endian"
        else:
            diagnostics.append(
                Diagnostic(level="error", message=f"Invalid TIFF endian marker {endian_bytes.hex()}", source="tiff_reader", offset=0)
            )
            return units, blocks, diagnostics

        magic = struct.unpack(f"{endian}H", reader.read_bytes(2, 2))[0]
        if magic != 42:
            diagnostics.append(
                Diagnostic(level="error", message=f"Invalid TIFF magic number {magic} (expected 42)", source="tiff_reader", offset=2)
            )
            return units, blocks, diagnostics

        first_ifd_offset = struct.unpack(f"{endian}I", reader.read_bytes(4, 4))[0]

        units.append(
            StructuralUnit(
                name="TIFF_HEADER",
                offset=0,
                length=8,
                data_offset=0,
                data_length=8,
                description=f"TIFF Header ({endian_name})",
            )
        )

        # Emit full TIFF block as EXIF metadata
        blocks.append(
            MetadataBlock(
                kind="EXIF",
                offset=0,
                length=size,
                raw_bytes=reader.get_all_bytes(),
                source_unit="TIFF_CONTAINER",
            )
        )

        # Walk IFD chain
        ifd_offset = first_ifd_offset
        ifd_index = 0
        visited_ifds = set()

        while ifd_offset > 0 and ifd_offset + 2 <= size:
            if ifd_offset in visited_ifds:
                diagnostics.append(
                    Diagnostic(level="warning", message=f"Cyclic IFD pointer detected at offset {ifd_offset}", source="tiff_reader", offset=ifd_offset)
                )
                break
            visited_ifds.add(ifd_offset)
            try:
                reader.check_unit_budget()
            except SourceBoundsError as e:
                diagnostics.append(
                    Diagnostic(level="warning", message=str(e), source="tiff_reader", offset=ifd_offset)
                )
                break

            entry_count = struct.unpack(f"{endian}H", reader.read_bytes(ifd_offset, 2))[0]
            ifd_len = 2 + entry_count * 12 + 4
            if ifd_offset + ifd_len > size:
                ifd_len = size - ifd_offset

            units.append(
                StructuralUnit(
                    name=f"IFD{ifd_index}",
                    offset=ifd_offset,
                    length=ifd_len,
                    data_offset=ifd_offset + 2,
                    data_length=entry_count * 12,
                    description=f"Image File Directory {ifd_index} ({entry_count} entries)",
                )
            )

            # Next IFD pointer is 4 bytes at the end of the entries table
            next_ptr_offset = ifd_offset + 2 + entry_count * 12
            if next_ptr_offset + 4 <= size:
                ifd_offset = struct.unpack(f"{endian}I", reader.read_bytes(next_ptr_offset, 4))[0]
            else:
                break
            ifd_index += 1

        return units, blocks, diagnostics
