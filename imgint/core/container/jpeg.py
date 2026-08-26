"""JPEG container reader parsing segments, APP markers, DQT, DHT, SOF, SOS, and trailing data."""

from __future__ import annotations
import struct
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError

JPEG_MARKER_NAMES = {
    0xD8: "SOI",
    0xD9: "EOI",
    0xC0: "SOF0 (Baseline DCT)",
    0xC1: "SOF1 (Extended Sequential)",
    0xC2: "SOF2 (Progressive DCT)",
    0xC3: "SOF3 (Lossless)",
    0xC4: "DHT (Huffman Table)",
    0xC5: "SOF5",
    0xC6: "SOF6",
    0xC7: "SOF7",
    0xC9: "SOF9",
    0xCA: "SOF10",
    0xCB: "SOF11",
    0xCD: "SOF13",
    0xCE: "SOF14",
    0xCF: "SOF15",
    0xCC: "DAC (Arithmetic Conditioning)",
    0xDA: "SOS (Start of Scan)",
    0xDB: "DQT (Quantization Table)",
    0xDC: "DNL",
    0xDD: "DRI (Restart Interval)",
    0xDE: "DHP",
    0xDF: "EXP",
    0xE0: "APP0 (JFIF)",
    0xE1: "APP1 (EXIF/XMP)",
    0xE2: "APP2 (ICC/MPF)",
    0xE3: "APP3",
    0xE4: "APP4",
    0xE5: "APP5",
    0xE6: "APP6",
    0xE7: "APP7",
    0xE8: "APP8",
    0xE9: "APP9",
    0xEA: "APP10",
    0xEB: "APP11 (C2PA/JUMBF)",
    0xEC: "APP12 (Picture Info)",
    0xED: "APP13 (Photoshop/IPTC)",
    0xEE: "APP14 (Adobe)",
    0xEF: "APP15",
    0xFE: "COM (Comment)",
}


class JpegContainerReader(ContainerReader):
    """Parses JPEG segments into StructuralUnits and MetadataBlocks."""

    def handles(self, format_name: str) -> bool:
        return format_name == "JPEG"

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        size = reader.size
        offset = 0

        # Verify SOI
        if size < 2 or reader.read_bytes(0, 2) != b"\xFF\xD8":
            diagnostics.append(
                Diagnostic(level="error", message="Missing JPEG SOI marker", source="jpeg_reader", offset=0)
            )
            return units, blocks, diagnostics

        units.append(
            StructuralUnit(
                name="SOI",
                offset=0,
                length=2,
                data_offset=2,
                data_length=0,
                description="Start of Image",
            )
        )
        offset = 2

        in_scan = False
        eoi_found = False

        while offset < size:
            try:
                reader.check_unit_budget()
            except SourceBoundsError as e:
                diagnostics.append(
                    Diagnostic(level="warning", message=str(e), source="jpeg_reader", offset=offset)
                )
                break

            # Find next marker: must begin with 0xFF
            b = reader.read_u8(offset)
            if b != 0xFF:
                if in_scan:
                    # Scan forward looking for next 0xFF
                    next_ff = reader.find(b"\xFF", offset)
                    if next_ff == -1:
                        # Reached EOF without marker
                        break
                    offset = next_ff
                    continue
                else:
                    diagnostics.append(
                        Diagnostic(
                            level="warning",
                            message=f"Expected marker prefix 0xFF at offset {offset}, got 0x{b:02X}",
                            source="jpeg_reader",
                            offset=offset,
                        )
                    )
                    # Advance to next 0xFF
                    next_ff = reader.find(b"\xFF", offset + 1)
                    if next_ff == -1:
                        break
                    offset = next_ff
                    continue

            # Skip fill bytes 0xFF
            while offset + 1 < size and reader.read_u8(offset + 1) == 0xFF:
                offset += 1

            if offset + 1 >= size:
                break

            marker = reader.read_u8(offset + 1)
            marker_offset = offset

            # 0x00 is byte stuffing in entropy stream
            if marker == 0x00:
                offset += 2
                continue

            # Restart markers RST0 - RST7 (0xD0 - 0xD7) have no payload length
            if 0xD0 <= marker <= 0xD7:
                units.append(
                    StructuralUnit(
                        name=f"RST{marker - 0xD0}",
                        offset=marker_offset,
                        length=2,
                        data_offset=marker_offset + 2,
                        data_length=0,
                        description=f"Restart Marker {marker - 0xD0}",
                    )
                )
                offset += 2
                continue

            # EOI (End of Image) 0xD9
            if marker == 0xD9:
                units.append(
                    StructuralUnit(
                        name="EOI",
                        offset=marker_offset,
                        length=2,
                        data_offset=marker_offset + 2,
                        data_length=0,
                        description="End of Image",
                    )
                )
                offset += 2
                eoi_found = True
                in_scan = False

                # Check for trailing data after EOI
                if offset < size:
                    trailing_len = size - offset
                    units.append(
                        StructuralUnit(
                            name="TRAILING_DATA",
                            offset=offset,
                            length=trailing_len,
                            data_offset=offset,
                            data_length=trailing_len,
                            description=f"Appended trailing bytes ({trailing_len} bytes) after EOI",
                            payload=reader.read_bytes(offset, min(trailing_len, 4096)),
                        )
                    )
                break

            # Markers with 2-byte big-endian length payload
            if offset + 4 > size:
                diagnostics.append(
                    Diagnostic(
                        level="warning",
                        message=f"Truncated marker 0xFF{marker:02X} at offset {marker_offset}",
                        source="jpeg_reader",
                        offset=marker_offset,
                    )
                )
                break

            payload_len = reader.read_u16_be(offset + 2)
            if payload_len < 2:
                diagnostics.append(
                    Diagnostic(
                        level="warning",
                        message=f"Invalid segment length {payload_len} for marker 0xFF{marker:02X}",
                        source="jpeg_reader",
                        offset=marker_offset,
                    )
                )
                offset += 2
                continue

            total_segment_len = 2 + payload_len
            data_offset = offset + 4
            data_len = payload_len - 2

            if data_offset + data_len > size:
                diagnostics.append(
                    Diagnostic(
                        level="warning",
                        message=f"Segment 0xFF{marker:02X} overflows file bounds ({data_offset + data_len} > {size})",
                        source="jpeg_reader",
                        offset=marker_offset,
                    )
                )
                data_len = max(0, size - data_offset)

            marker_name = JPEG_MARKER_NAMES.get(marker, f"MARKER_0x{marker:02X}")
            payload_bytes = reader.read_bytes(data_offset, data_len)

            unit = StructuralUnit(
                name=marker_name.split()[0],
                offset=marker_offset,
                length=total_segment_len,
                data_offset=data_offset,
                data_length=data_len,
                description=marker_name,
                payload=payload_bytes,
            )
            units.append(unit)

            # Metadata extraction from APP markers
            if marker == 0xE1:  # APP1
                if payload_bytes.startswith(b"Exif\x00\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="EXIF",
                            offset=data_offset + 6,
                            length=data_len - 6,
                            raw_bytes=payload_bytes[6:],
                            source_unit="APP1_EXIF",
                        )
                    )
                elif payload_bytes.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="XMP",
                            offset=data_offset + 29,
                            length=data_len - 29,
                            raw_bytes=payload_bytes[29:],
                            source_unit="APP1_XMP",
                        )
                    )
                elif payload_bytes.startswith(b"http://ns.adobe.com/xmp/extension/\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="XMP_EXT",
                            offset=data_offset + 35,
                            length=data_len - 35,
                            raw_bytes=payload_bytes[35:],
                            source_unit="APP1_XMP_EXTENDED",
                        )
                    )
            elif marker == 0xE2:  # APP2
                if payload_bytes.startswith(b"ICC_PROFILE\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="ICC",
                            offset=data_offset + 12,
                            length=data_len - 12,
                            raw_bytes=payload_bytes[12:],
                            source_unit="APP2_ICC",
                        )
                    )
                elif payload_bytes.startswith(b"MPF\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="MPF",
                            offset=data_offset + 4,
                            length=data_len - 4,
                            raw_bytes=payload_bytes[4:],
                            source_unit="APP2_MPF",
                        )
                    )
            elif marker == 0xED:  # APP13 (Photoshop / IPTC)
                if payload_bytes.startswith(b"Photoshop 3.0\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="IPTC_8BIM",
                            offset=data_offset + 14,
                            length=data_len - 14,
                            raw_bytes=payload_bytes[14:],
                            source_unit="APP13_PHOTOSHOP",
                        )
                    )
            elif marker == 0xEB:  # APP11 (C2PA)
                blocks.append(
                    MetadataBlock(
                        kind="C2PA",
                        offset=data_offset,
                        length=data_len,
                        raw_bytes=payload_bytes,
                        source_unit="APP11_C2PA",
                    )
                )
            elif marker == 0xE0:  # APP0 (JFIF)
                if payload_bytes.startswith(b"JFIF\x00"):
                    blocks.append(
                        MetadataBlock(
                            kind="JFIF",
                            offset=data_offset,
                            length=data_len,
                            raw_bytes=payload_bytes,
                            source_unit="APP0_JFIF",
                        )
                    )

            if marker == 0xDA:  # SOS (Start of Scan)
                in_scan = True
                offset = data_offset + data_len
                # In scan mode, we seek for the next marker (like EOI)
                continue

            offset += total_segment_len

        return units, blocks, diagnostics
