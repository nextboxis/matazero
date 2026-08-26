"""GIF container structure reader for animated and static GIF files."""

from __future__ import annotations
from typing import List, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader


class GifContainerReader(ContainerReader):
    """Parses GIF container structures (Header, Logical Screen Descriptor, Blocks, Extensions)."""

    def handles(self, format_name: str) -> bool:
        return format_name == "GIF"

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        if reader.size < 13:
            diagnostics.append(Diagnostic(level="error", message="GIF file too small", source="gif_reader"))
            return units, blocks, diagnostics

        # Header (6 bytes: GIF87a or GIF89a)
        sig = reader.read_bytes(0, 6)
        units.append(
            StructuralUnit(
                name="HEADER",
                offset=0,
                length=6,
                data_offset=0,
                data_length=6,
                description=f"GIF Header ({sig.decode('ascii', errors='replace')})",
            )
        )

        # Logical Screen Descriptor (7 bytes)
        lsd = reader.read_bytes(6, 7)
        w = int.from_bytes(lsd[:2], "little")
        h = int.from_bytes(lsd[2:4], "little")
        has_gct = bool(lsd[4] & 0x80)
        gct_size = 3 * (2 ** ((lsd[4] & 0x07) + 1)) if has_gct else 0

        units.append(
            StructuralUnit(
                name="LSD",
                offset=6,
                length=7,
                data_offset=6,
                data_length=7,
                description=f"Logical Screen Descriptor ({w}x{h} px)",
            )
        )

        offset = 13
        if has_gct and gct_size > 0:
            units.append(
                StructuralUnit(
                    name="GCT",
                    offset=offset,
                    length=gct_size,
                    data_offset=offset,
                    data_length=gct_size,
                    description=f"Global Color Table ({gct_size // 3} colors)",
                )
            )
            offset += gct_size

        frame_count = 0
        # Parse blocks until Trailer (0x3B)
        while offset < reader.size and reader.can_read(1, offset):
            intro = reader.read_bytes(offset, 1)
            if not intro:
                break

            if intro == b"\x3B":  # Trailer
                units.append(
                    StructuralUnit(
                        name="TRAILER",
                        offset=offset,
                        length=1,
                        data_offset=offset,
                        data_length=0,
                        description="End of GIF stream",
                    )
                )
                offset += 1
                if offset < reader.size:
                    trailing_len = reader.size - offset
                    units.append(
                        StructuralUnit(
                            name="TRAILING_DATA",
                            offset=offset,
                            length=trailing_len,
                            data_offset=offset,
                            data_length=trailing_len,
                            description=f"Appended trailing bytes ({trailing_len} bytes) after GIF Trailer",
                            payload=reader.read_bytes(offset, min(trailing_len, 4096)),
                        )
                    )
                break

            elif intro == b"\x21":  # Extension Block
                if offset + 2 > reader.size:
                    break
                label = reader.read_bytes(offset + 1, 1)
                ext_name = f"EXT_0x{label[0]:02X}"
                desc = "Extension Block"
                if label == b"\xF9":
                    ext_name = "GRAPHIC_CONTROL"
                    desc = "Graphic Control Extension (Animation Frame Timing)"
                elif label == b"\xFE":
                    ext_name = "COMMENT"
                    desc = "Comment Extension"
                elif label == b"\xFF":
                    ext_name = "APPLICATION"
                    desc = "Application Extension (e.g. NETSCAPE2.0 looping)"
                elif label == b"\x01":
                    ext_name = "PLAIN_TEXT"
                    desc = "Plain Text Extension"

                # Skip sub-blocks
                block_start = offset
                offset += 2
                while offset < reader.size:
                    sub_len_b = reader.read_bytes(offset, 1)
                    if not sub_len_b:
                        break
                    sub_len = sub_len_b[0]
                    offset += 1
                    if sub_len == 0:
                        break
                    offset += sub_len

                ext_len = offset - block_start
                units.append(
                    StructuralUnit(
                        name=ext_name,
                        offset=block_start,
                        length=ext_len,
                        data_offset=block_start + 2,
                        data_length=ext_len - 2,
                        description=desc,
                    )
                )

            elif intro == b"\x2C":  # Image Descriptor
                frame_count += 1
                img_start = offset
                offset += 10  # 1 (0x2C) + 8 (coords) + 1 (packed)
                if offset > reader.size:
                    break
                # Local color table if present
                packed = reader.read_bytes(img_start + 9, 1)[0]
                if packed & 0x80:
                    lct_size = 3 * (2 ** ((packed & 0x07) + 1))
                    offset += lct_size

                # LZW Minimum Code Size
                offset += 1
                # Skip raster data sub-blocks
                while offset < reader.size:
                    sub_len_b = reader.read_bytes(offset, 1)
                    if not sub_len_b:
                        break
                    sub_len = sub_len_b[0]
                    offset += 1
                    if sub_len == 0:
                        break
                    offset += sub_len

                img_len = offset - img_start
                units.append(
                    StructuralUnit(
                        name=f"FRAME_{frame_count}",
                        offset=img_start,
                        length=img_len,
                        data_offset=img_start,
                        data_length=img_len,
                        description=f"GIF Image Frame #{frame_count}",
                    )
                )
            else:
                # Unknown byte, stop safely
                offset += 1

        return units, blocks, diagnostics
