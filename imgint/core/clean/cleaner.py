"""Lossless metadata stripper for self-audit privacy cleaning per SRD FR-12 and FR-10.9."""

from __future__ import annotations
import struct
from pathlib import Path
from typing import Optional, Tuple
from imgint.core.sniff.detector import FormatDetector
from imgint.core.source.reader import BoundedReader


class MetadataCleaner:
    """Removes metadata chunks without re-encoding image stream bytes."""

    @classmethod
    def clean_file(
        cls, input_path: str | Path, output_path: Optional[str | Path] = None
    ) -> Tuple[bytes, int, int]:
        """Cleans metadata from input file.

        Returns:
            (cleaned_bytes, original_size, cleaned_size)
        """
        reader = BoundedReader(input_path)
        detected = FormatDetector.detect(reader)
        data = reader.get_all_bytes()

        if detected.format_name == "JPEG":
            cleaned = cls._clean_jpeg(data)
        elif detected.format_name == "PNG":
            cleaned = cls._clean_png(data)
        else:
            raise ValueError(f"Format {detected.format_name} not supported for metadata cleaning")

        orig_size = len(data)
        clean_size = len(cleaned)

        if output_path:
            out_p = Path(output_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "wb") as f:
                f.write(cleaned)

        return cleaned, orig_size, clean_size

    @classmethod
    def _clean_jpeg(cls, data: bytes) -> bytes:
        """Strips APP1-APP15 segments while preserving DQT, DHT, SOF, SOS image stream."""
        if len(data) < 2 or data[:2] != b"\xFF\xD8":
            return data

        out = bytearray(b"\xFF\xD8")
        offset = 2
        size = len(data)

        # Retain standard segments needed for rendering: DQT (0xDB), DHT (0xC4), SOF (0xC0..0xCF), SOS (0xDA), DRI (0xDD), APP0 (JFIF 0xE0)
        ALLOWED_MARKERS = {0xE0, 0xDB, 0xC4, 0xC0, 0xC1, 0xC2, 0xC3, 0xDD, 0xDA}

        while offset < size:
            if data[offset] != 0xFF:
                offset += 1
                continue

            # Skip fill bytes
            while offset + 1 < size and data[offset + 1] == 0xFF:
                offset += 1

            if offset + 1 >= size:
                break

            marker = data[offset + 1]
            if marker == 0xD9:  # EOI
                out.extend(b"\xFF\xD9")
                break

            if marker == 0xDA:  # SOS (Start of Scan) - rest is entropy data until EOI
                eoi_idx = data.find(b"\xFF\xD9", offset)
                if eoi_idx != -1:
                    out.extend(data[offset : eoi_idx + 2])
                else:
                    out.extend(data[offset:])
                break

            if offset + 4 > size:
                break

            seg_len = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
            total_seg_len = 2 + seg_len

            if marker in ALLOWED_MARKERS:
                out.extend(data[offset : offset + total_seg_len])

            offset += total_seg_len

        return bytes(out)

    @classmethod
    def _clean_png(cls, data: bytes) -> bytes:
        """Strips auxiliary metadata chunks from PNG while preserving IHDR, PLTE, IDAT, IEND."""
        if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
            return data

        out = bytearray(b"\x89PNG\r\n\x1a\n")
        offset = 8
        size = len(data)

        # Critical chunks to preserve
        CRITICAL_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS"}

        while offset + 8 <= size:
            chunk_len = struct.unpack(">I", data[offset : offset + 4])[0]
            chunk_type = data[offset + 4 : offset + 8]
            total_chunk_len = 12 + chunk_len

            if offset + total_chunk_len > size:
                break

            if chunk_type in CRITICAL_CHUNKS:
                out.extend(data[offset : offset + total_chunk_len])

            offset += total_chunk_len
            if chunk_type == b"IEND":
                break

        return bytes(out)
