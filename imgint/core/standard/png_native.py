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
                fields.append(Field(standard="PNG", name=f"png:{keyword}", value=val, raw_value=v.hex(), value_type="STRING"))
                findings.append(
                    Finding(
                        name=f"png_text_{keyword.lower()}",
                        value=val,
                        tier=1,
                        extractor="png_native_parser",
                        confidence=Confidence.OBSERVED,
                        caveat=None,
                        provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=block.offset, length=block.length, standard="PNG"),
                    )
                )

        elif "zTXt" in source_unit:
            # Keyword\0CompressionMethod(1 byte)\0CompressedText
            if b"\x00" in data:
                k, rest = data.split(b"\x00", 1)
                keyword = k.decode("latin-1", errors="replace").strip()
                if len(rest) > 1:
                    compressed_data = rest[1:]  # Skip compression method byte
                    try:
                        decompressed = zlib.decompress(compressed_data)
                        val = decompressed.decode("latin-1", errors="replace").strip()
                        fields.append(Field(standard="PNG", name=f"png:{keyword}", value=val, raw_value=val, value_type="STRING"))
                        findings.append(
                            Finding(
                                name=f"png_ztxt_{keyword.lower()}",
                                value=val,
                                tier=1,
                                extractor="png_native_parser",
                                confidence=Confidence.OBSERVED,
                                caveat=None,
                                provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=block.offset, length=block.length, standard="PNG"),
                            )
                        )
                    except Exception as e:
                        diagnostics.append(Diagnostic(level="warning", message=f"zTXt decompression failed: {e}", source="png_native_parser", offset=block.offset))

        elif "iTXt" in source_unit:
            # Keyword\0CompFlag\0CompMethod\0LangTag\0TransKey\0Text
            parts = data.split(b"\x00", 4)
            if len(parts) >= 5:
                keyword = parts[0].decode("utf-8", errors="replace").strip()
                text_bytes = parts[4]
                comp_flag = data[len(parts[0]) + 1] if len(data) > len(parts[0]) + 1 else 0
                if comp_flag == 1:
                    try:
                        text_bytes = zlib.decompress(text_bytes)
                    except Exception:
                        pass
                val = text_bytes.decode("utf-8", errors="replace").strip()
                fields.append(Field(standard="PNG", name=f"png:{keyword}", value=val, raw_value=val, value_type="STRING"))
                findings.append(
                    Finding(
                        name=f"png_itxt_{keyword.lower()}",
                        value=val,
                        tier=1,
                        extractor="png_native_parser",
                        confidence=Confidence.OBSERVED,
                        caveat=None,
                        provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=block.offset, length=block.length, standard="PNG"),
                    )
                )

        elif "tIME" in source_unit and len(data) >= 7:
            year, month, day, hour, minute, second = struct.unpack(">HBBBBB", data[:7])
            time_str = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"
            fields.append(Field(standard="PNG", name="png:tIME", value=time_str, raw_value=time_str, value_type="TIMESTAMP"))
            findings.append(
                Finding(
                    name="png_time_stamp",
                    value=time_str,
                    tier=1,
                    extractor="png_native_parser",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="standard", extractor="png_native_parser", offset=block.offset, length=block.length, standard="PNG"),
                )
            )

        elif "pHYs" in source_unit and len(data) >= 9:
            ppu_x, ppu_y, unit_spec = struct.unpack(">IIB", data[:9])
            unit_name = "meter" if unit_spec == 1 else "unknown"
            fields.append(Field(standard="PNG", name="png:pHYs", value=f"{ppu_x}x{ppu_y} per {unit_name}", raw_value=f"{ppu_x},{ppu_y},{unit_spec}", value_type="STRING"))

        return fields, findings, diagnostics
