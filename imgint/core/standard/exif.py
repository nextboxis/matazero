"""EXIF 2.32 parser with integer-rational preservation and opaque MakerNote handling per SRD FR-2.1 - FR-2.3, FR-2.10."""

from __future__ import annotations
import struct
from typing import Any, Dict, List, Optional, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.standard.base import BlockParser

EXIF_TAGS = {
    # IFD0 / Main
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifOffset",
    0x8825: "GPSInfo",
    # SubIFD 0x8769
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8822: "ExposureProgram",
    0x8827: "ISOSpeedRatings",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal",
    0x9012: "OffsetTimeDigitized",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x9204: "ExposureBiasValue",
    0x9207: "MeteringMode",
    0x9208: "LightSource",
    0x9209: "Flash",
    0x920A: "FocalLength",
    0x927C: "MakerNote",  # Preserved as opaque blob per FR-2.10
    0x9286: "UserComment",
    0x9290: "SubSecTime",
    0x9291: "SubSecTimeOriginal",
    0x9292: "SubSecTimeDigitized",
    0xA000: "FlashpixVersion",
    0xA001: "ColorSpace",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA005: "InteropOffset",
    0xA405: "FocalLengthIn35mmFilm",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA433: "LensMake",
    0xA434: "LensModel",
    0xA435: "LensSerialNumber",
    # GPS IFD 0x8825
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0008: "GPSSatellites",
    0x0009: "GPSStatus",
    0x000A: "GPSMeasureMode",
    0x000B: "GPSDOP",
    0x000C: "GPSSpeedRef",
    0x000D: "GPSSpeed",
    0x0012: "GPSMapDatum",
    0x001D: "GPSDateStamp",
    0x001E: "GPSDifferential",
    # IFD1 (Thumbnail)
    0x0201: "JPEGInterchangeFormat",
    0x0202: "JPEGInterchangeFormatLength",
}


class ExifParser(BlockParser):
    """Parses EXIF IFDs from raw TIFF byte blocks."""

    def handles(self, kind: str) -> bool:
        return kind in ("EXIF", "TIFF_EXIF")

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        data = block.raw_bytes
        if data.startswith(b"Exif\x00\x00"):
            data = data[6:]
        size = len(data)
        if size < 8:
            diagnostics.append(
                Diagnostic(level="warning", message="EXIF block too small (< 8 bytes)", source="exif_parser", offset=block.offset)
            )
            return fields, findings, diagnostics

        endian_str = data[:2]
        if endian_str == b"II":
            endian = "<"
        elif endian_str == b"MM":
            endian = ">"
        else:
            diagnostics.append(
                Diagnostic(level="warning", message="Invalid EXIF endianness header", source="exif_parser", offset=block.offset)
            )
            return fields, findings, diagnostics

        magic = struct.unpack(f"{endian}H", data[2:4])[0]
        if magic != 42:
            diagnostics.append(
                Diagnostic(level="warning", message=f"Invalid EXIF TIFF magic {magic}", source="exif_parser", offset=block.offset)
            )
            return fields, findings, diagnostics

        first_ifd_offset = struct.unpack(f"{endian}I", data[4:8])[0]

        visited_offsets = set()
        max_ifd_limit = 50

        def parse_ifd(ifd_offset: int, ifd_name: str, depth: int = 0) -> None:
            if depth > 10 or len(visited_offsets) >= max_ifd_limit:
                return
            if ifd_offset in visited_offsets or ifd_offset <= 0 or ifd_offset + 2 > size:
                return
            visited_offsets.add(ifd_offset)

            entry_count = struct.unpack(f"{endian}H", data[ifd_offset : ifd_offset + 2])[0]
            curr = ifd_offset + 2

            TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}

            for _ in range(entry_count):
                if curr + 12 > size:
                    break

                entry_rel_offset = curr
                tag_id, field_type, count, val_or_offset = struct.unpack(
                    f"{endian}HHI I", data[curr : curr + 12]
                )
                curr += 12

                tag_hex = f"0x{tag_id:04X}"
                tag_name = EXIF_TAGS.get(tag_id, f"Tag_{tag_hex}")
                type_size = TYPE_SIZES.get(field_type, 1)
                total_val_bytes = count * type_size

                tag_abs_offset = block.offset + entry_rel_offset
                if total_val_bytes <= 4:
                    val_abs_offset = block.offset + entry_rel_offset + 8
                    val_len = total_val_bytes
                else:
                    val_abs_offset = block.offset + val_or_offset
                    val_len = total_val_bytes

                # FR-2.10: Preserve MakerNote as opaque blob
                if tag_id == 0x927C:
                    maker_offset = val_or_offset
                    maker_len = count
                    maker_abs_offset = block.offset + maker_offset if maker_offset < size else block.offset
                    fields.append(
                        Field(
                            standard="EXIF",
                            tag_id=tag_hex,
                            name="MakerNote",
                            value=f"<Opaque MakerNote: {maker_len} bytes at offset {maker_offset}>",
                            raw_value=maker_offset,
                            value_type="OPAQUE_BLOB",
                            description="Preserved as opaque blob without interpretation per FR-2.10",
                            offset=tag_abs_offset,
                            value_offset=maker_abs_offset,
                            length=maker_len,
                        )
                    )
                    findings.append(
                        Finding(
                            name="exif_makernote_present",
                            value={"offset": maker_offset, "length": maker_len, "absolute_value_offset": maker_abs_offset},
                            tier=1,
                            extractor="exif_parser",
                            confidence=Confidence.OBSERVED,
                            caveat=None,
                            provenance=Provenance(
                                source_layer="standard",
                                extractor="exif_parser",
                                offset=maker_abs_offset,
                                length=maker_len,
                                standard="EXIF",
                                tag_id=tag_hex,
                            ),
                        )
                    )
                    # Extract decoded MakerNote sub-fields if recognized
                    decoded_fields = self._parse_makernote(data, maker_offset, maker_len, endian, block.offset)
                    fields.extend(decoded_fields)
                    continue

                # Recurse into sub-IFDs
                if tag_id == 0x8769:  # ExifOffset
                    parse_ifd(val_or_offset, "ExifSubIFD", depth + 1)
                    continue
                elif tag_id == 0x8825:  # GPSInfo
                    parse_ifd(val_or_offset, "GPSInfo", depth + 1)
                    continue
                elif tag_id == 0xA005:  # InteropOffset
                    parse_ifd(val_or_offset, "InteropIFD", depth + 1)
                    continue

                # Value extraction per type
                val, val_type_name = self._extract_value(data, endian, field_type, count, val_or_offset)
                if val is not None:
                    fields.append(
                        Field(
                            standard="EXIF",
                            tag_id=tag_hex,
                            name=f"{ifd_name}:{tag_name}" if ifd_name != "IFD0" else tag_name,
                            value=val,
                            raw_value=val_or_offset,
                            value_type=val_type_name,
                            offset=tag_abs_offset,
                            value_offset=val_abs_offset,
                            length=val_len,
                        )
                    )
                    # Produce Tier-1 observed finding for prominent metadata tags
                    if tag_id in (0x010F, 0x0110, 0x0131, 0x0132, 0x9003, 0x9004, 0xA434, 0x0002, 0x0004, 0x0006, 0x0007, 0x001D, 0x011A, 0x011B, 0xA002, 0xA003):
                        findings.append(
                            Finding(
                                name=f"exif_{tag_name.lower()}",
                                value=val,
                                tier=1,
                                extractor="exif_parser",
                                confidence=Confidence.OBSERVED,
                                caveat=None,
                                provenance=Provenance(
                                    source_layer="standard",
                                    extractor="exif_parser",
                                    offset=val_abs_offset,
                                    length=val_len,
                                    standard="EXIF",
                                    tag_id=tag_hex,
                                ),
                            )
                        )

            # Check next IFD pointer (e.g. IFD1)
            if curr + 4 <= size:
                next_ifd = struct.unpack(f"{endian}I", data[curr : curr + 4])[0]
                if next_ifd > 0 and next_ifd < size:
                    parse_ifd(next_ifd, "IFD1", depth + 1)

        parse_ifd(first_ifd_offset, "IFD0")
        return fields, findings, diagnostics

    def _extract_value(
        self, data: bytes, endian: str, field_type: int, count: int, val_or_offset: int
    ) -> Tuple[Any, str]:
        size = len(data)
        # Type map: 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL, 6=SBYTE, 7=UNDEF, 8=SSHORT, 9=SLONG, 10=SRATIONAL, 11=FLOAT, 12=DOUBLE
        if field_type == 2:  # ASCII
            if count <= 4:
                raw = struct.pack(f"{endian}I", val_or_offset)[:count]
            else:
                if val_or_offset + count <= size:
                    raw = data[val_or_offset : val_or_offset + count]
                else:
                    raw = b""
            s = raw.split(b"\x00")[0].decode("utf-8", errors="replace").strip()
            return s, "ASCII"

        elif field_type == 3:  # SHORT
            if count == 1:
                if endian == ">":
                    s_val = (val_or_offset >> 16) if (val_or_offset >> 16) != 0 else (val_or_offset & 0xFFFF)
                    return s_val, "SHORT"
                return (val_or_offset & 0xFFFF), "SHORT"
            else:
                vals = []
                off = val_or_offset
                for _ in range(min(count, 128)):
                    if off + 2 <= size:
                        vals.append(struct.unpack(f"{endian}H", data[off : off + 2])[0])
                        off += 2
                return vals, "SHORT[]"

        elif field_type == 4:  # LONG
            if count == 1:
                return val_or_offset, "LONG"
            else:
                vals = []
                off = val_or_offset
                for _ in range(min(count, 128)):
                    if off + 4 <= size:
                        vals.append(struct.unpack(f"{endian}I", data[off : off + 4])[0])
                        off += 4
                return vals, "LONG[]"

        elif field_type in (5, 10):  # RATIONAL / SRATIONAL (Preserved as integer pair per FR-2.3)
            fmt = f"{endian}ii" if field_type == 10 else f"{endian}II"
            typename = "SRATIONAL" if field_type == 10 else "RATIONAL"
            if count == 1:
                if val_or_offset + 8 <= size:
                    num, den = struct.unpack(fmt, data[val_or_offset : val_or_offset + 8])
                    return [num, den], typename
                return None, typename
            else:
                pairs = []
                off = val_or_offset
                for _ in range(min(count, 32)):
                    if off + 8 <= size:
                        num, den = struct.unpack(fmt, data[off : off + 8])
                        pairs.append([num, den])
                        off += 8
                return pairs, f"{typename}[]"

        elif field_type == 1:  # BYTE
            return val_or_offset & 0xFF, "BYTE"

        elif field_type == 7:  # UNDEFINED
            if count <= 4:
                return list(struct.pack(f"{endian}I", val_or_offset)[:count]), "UNDEFINED"
            return f"<Undefined blob: {count} bytes>", "UNDEFINED"

        return val_or_offset, f"TYPE_{field_type}"

    def _parse_makernote(
        self, data: bytes, maker_offset: int, maker_len: int, parent_endian: str, block_abs_offset: int
    ) -> List[Field]:
        if maker_offset + maker_len > len(data):
            return []
        raw_blob = data[maker_offset : maker_offset + maker_len]
        if len(raw_blob) < 8:
            return []

        fields: List[Field] = []

        # 1. Nikon 2/3 (Starts with b"Nikon\x00\x02" or b"Nikon\x00\x01")
        if raw_blob.startswith(b"Nikon\x00\x02") or raw_blob.startswith(b"Nikon\x00\x01"):
            hdr_len = 10 if raw_blob.startswith(b"Nikon\x00\x02") else 8
            sub_data = raw_blob[hdr_len:]
            if len(sub_data) >= 8:
                nikon_endian = "<" if sub_data[:2] == b"II" else ">" if sub_data[:2] == b"MM" else parent_endian
                if sub_data[:2] in (b"II", b"MM") and len(sub_data) >= 8:
                    ifd_start = struct.unpack(f"{nikon_endian}I", sub_data[4:8])[0]
                else:
                    ifd_start = 0
                nikon_tags = {
                    0x0001: "NikonMakerNoteVersion",
                    0x0002: "NikonISOSetting",
                    0x001D: "NikonSerialNumber",
                    0x00A7: "NikonShutterCount",
                    0x0084: "NikonLensInfo",
                }
                fields.extend(self._parse_sub_ifd(sub_data, ifd_start, nikon_endian, nikon_tags, "Nikon", maker_offset + hdr_len, block_abs_offset))

        # 2. Apple (Starts with b"Apple iOS\x00")
        elif raw_blob.startswith(b"Apple iOS\x00"):
            sub_data = raw_blob[14:]
            apple_tags = {
                0x0001: "AppleMakerNoteVersion",
                0x0003: "AppleRunTime",
                0x000E: "AppleHDRImageType",
                0x0017: "AppleSceneFlags",
            }
            fields.extend(self._parse_sub_ifd(sub_data, 0, parent_endian, apple_tags, "Apple", maker_offset + 14, block_abs_offset))

        # 3. Sony (Starts with b"SONY DSC \x00")
        elif raw_blob.startswith(b"SONY DSC \x00") or raw_blob.startswith(b"SONY MOBILE\x00"):
            hdr_len = 12
            sub_data = raw_blob[hdr_len:]
            sony_tags = {
                0x2001: "SonyModelID",
                0x2010: "SonySequenceNumber",
            }
            fields.extend(self._parse_sub_ifd(sub_data, 0, parent_endian, sony_tags, "Sony", maker_offset + hdr_len, block_abs_offset))

        # 4. Canon (Starts directly with entry count)
        elif len(raw_blob) >= 4:
            canon_tags = {
                0x0001: "CanonCameraSettings",
                0x0004: "CanonShotInfo",
                0x0006: "CanonImageType",
                0x0007: "CanonFirmwareVersion",
                0x000C: "CanonSerialNumber",
                0x0095: "CanonLensModel",
            }
            res = self._parse_sub_ifd(raw_blob, 0, parent_endian, canon_tags, "Canon", maker_offset, block_abs_offset)
            if res:
                fields.extend(res)

        return fields

    def _parse_sub_ifd(
        self, sub_data: bytes, ifd_offset: int, endian: str, tag_dict: Dict[int, str], prefix: str, base_offset: int, block_abs_offset: int
    ) -> List[Field]:
        fields: List[Field] = []
        size = len(sub_data)
        if ifd_offset + 2 > size:
            return fields

        num_entries = struct.unpack(f"{endian}H", sub_data[ifd_offset : ifd_offset + 2])[0]
        if num_entries == 0 or num_entries > 256 or (ifd_offset + 2 + num_entries * 12) > size:
            return fields

        curr = ifd_offset + 2
        for _ in range(num_entries):
            if curr + 12 > size:
                break
            tag_id, f_type, count, val_or_offset = struct.unpack(f"{endian}HHI I", sub_data[curr : curr + 12])
            tag_name = tag_dict.get(tag_id, f"{prefix}Tag_0x{tag_id:04X}")
            val, val_type = self._extract_value(sub_data, endian, f_type, count, val_or_offset)
            if val is not None:
                fields.append(
                    Field(
                        standard="EXIF",
                        tag_id=f"0x{tag_id:04X}",
                        name=f"MakerNote:{tag_name}",
                        value=val,
                        raw_value=val_or_offset,
                        value_type=val_type,
                        offset=block_abs_offset + base_offset + curr,
                        value_offset=block_abs_offset + base_offset + (val_or_offset if count > 4 else curr + 8),
                        length=count,
                    )
                )
            curr += 12
        return fields
