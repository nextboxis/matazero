"""PNG native chunk parser (tEXt, zTXt, iTXt, tIME, pHYs) per SRD FR-2.8."""

from __future__ import annotations
import struct
import zlib
from typing import Dict, List, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.standard.base import BlockParser


class PngNativeParser(BlockParser):
    """Parses PNG text chunks and physical metadata."""

    def handles(self, kind: str) -> bool:
        return kind in ("PNG_TEXT", "PNG_NATIVE")

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        data = block.raw_bytes
        source_unit = block.source_unit or ""

        if "tEXt" in source_unit:
            # Keyword\0Text
            if b"\x00" in data:
                k, v = data.split(b"\x00", 1)
                keyword = k.decode("latin-1", errors="replace").strip()
                val = v.decode("latin-1", errors="replace").strip()
                val_abs_offset = block.offset + len(k) + 1
                fields.append(Field(standard="PNG", name=f"png:{keyword}", value=val, raw_value=v.hex(), value_type="STRING", offset=block.offset, value_offset=val_abs_offset, length=len(v)))
                findings.append(
                    Finding(
                        name=f"png_text_{keyword.lower()}",
                        value=val,
                        tier=1,
                        extractor="png_native_parser",
                        confidence=Confidence.OBSERVED,
                        caveat=None,
                        provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=val_abs_offset, length=len(v), standard="PNG"),
                    )
                )

        elif "zTXt" in source_unit:
            # Keyword\0CompressionMethod(1 byte)\0CompressedText
            if b"\x00" in data:
                k, rest = data.split(b"\x00", 1)
                keyword = k.decode("latin-1", errors="replace").strip()
                val_abs_offset = block.offset + len(k) + 2
                if len(rest) > 1:
                    compressed_data = rest[1:]  # Skip compression method byte
                    try:
                        decompressed = zlib.decompress(compressed_data)
                        val = decompressed.decode("latin-1", errors="replace").strip()
                        fields.append(Field(standard="PNG", name=f"png:{keyword}", value=val, raw_value=val, value_type="STRING", offset=block.offset, value_offset=val_abs_offset, length=len(compressed_data)))
                        findings.append(
                            Finding(
                                name=f"png_ztxt_{keyword.lower()}",
                                value=val,
                                tier=1,
                                extractor="png_native_parser",
                                confidence=Confidence.OBSERVED,
                                caveat=None,
                                provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=val_abs_offset, length=len(compressed_data), standard="PNG"),
                            )
                        )
                    except Exception as e:
                        diagnostics.append(Diagnostic(level="warning", message=f"zTXt decompression failed: {e}", source="png_native_parser", offset=block.offset))

        elif "iTXt" in source_unit:
            # Structure: Keyword\0CompFlag(1B)CompMethod(1B)LangTag\0TransKey\0Text
            if b"\x00" in data:
                null_idx = data.find(b"\x00")
                keyword = data[:null_idx].decode("utf-8", errors="replace").strip()
                val_abs_offset = block.offset + null_idx + 3
                if len(data) >= null_idx + 3:
                    comp_flag = data[null_idx + 1]
                    comp_method = data[null_idx + 2]
                    rest = data[null_idx + 3:]
                    rest_parts = rest.split(b"\x00", 2)
                    text_bytes = rest_parts[2] if len(rest_parts) == 3 else (rest_parts[-1] if rest_parts else b"")
                    if comp_flag == 1 and text_bytes:
                        try:
                            text_bytes = zlib.decompress(text_bytes)
                        except Exception as e:
                            diagnostics.append(Diagnostic(level="warning", message=f"iTXt decompression failed: {e}", source="png_native_parser", offset=block.offset))
                    val = text_bytes.decode("utf-8", errors="replace").strip()
                    fields.append(Field(standard="PNG", name=f"png:{keyword}", value=val, raw_value=val, value_type="STRING", offset=block.offset, value_offset=val_abs_offset, length=len(text_bytes)))
                    findings.append(
                        Finding(
                            name=f"png_itxt_{keyword.lower()}",
                            value=val,
                            tier=1,
                            extractor="png_native_parser",
                            confidence=Confidence.OBSERVED,
                            caveat=None,
                            provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=val_abs_offset, length=len(text_bytes), standard="PNG"),
                        )
                    )

        elif "tIME" in source_unit and len(data) >= 7:
            year, month, day, hour, minute, second = struct.unpack(">HBBBBB", data[:7])
            time_str = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"
            fields.append(Field(standard="PNG", name="png:tIME", value=time_str, raw_value=time_str, value_type="TIMESTAMP", offset=block.offset, value_offset=block.offset, length=7))
            findings.append(
                Finding(
                    name="png_time_stamp",
                    value=time_str,
                    tier=1,
                    extractor="png_native_parser",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=block.offset, length=7, standard="PNG"),
                )
            )

        elif "pHYs" in source_unit and len(data) >= 9:
            ppu_x, ppu_y, unit_spec = struct.unpack(">IIB", data[:9])
            unit_name = "meter" if unit_spec == 1 else "unknown"
            fields.append(Field(standard="PNG", name="png:pHYs", value=f"{ppu_x}x{ppu_y} per {unit_name}", raw_value=f"{ppu_x},{ppu_y},{unit_spec}", value_type="STRING", offset=block.offset, value_offset=block.offset, length=9))

        return fields, findings, diagnostics
