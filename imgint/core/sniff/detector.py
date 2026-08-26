"""Magic-byte format detector and extension mismatch checker per SRD FR-1.1 - FR-1.5."""

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.source.reader import BoundedReader


@dataclass
class DetectedFormat:
    format_name: str     # "JPEG", "PNG", "TIFF", "WEBP", "HEIC", "AVIF", "GIF", "BMP", "PSD", "SVG", "UNKNOWN"
    mime_type: str
    is_supported: bool
    magic_bytes: bytes
    magic_hex: str
    expected_extensions: List[str]


class FormatDetector:
    """Detects file format strictly from magic bytes."""

    @staticmethod
    def detect(reader: BoundedReader) -> DetectedFormat:
        size = reader.size
        head = reader.read_bytes(0, min(64, size))
        magic_hex = head[:8].hex(" ").upper()

        if len(head) >= 3 and head[:3] == b"\xFF\xD8\xFF":
            return DetectedFormat(
                format_name="JPEG",
                mime_type="image/jpeg",
                is_supported=True,
                magic_bytes=head[:3],
                magic_hex=magic_hex,
                expected_extensions=[".jpg", ".jpeg", ".jpe", ".jfif"],
            )

        if len(head) >= 8 and head[:8] == b"\x89PNG\r\n\x1a\n":
            return DetectedFormat(
                format_name="PNG",
                mime_type="image/png",
                is_supported=True,
                magic_bytes=head[:8],
                magic_hex=magic_hex,
                expected_extensions=[".png"],
            )

        if len(head) >= 4 and head[:4] in (b"II*\x00", b"MM\x00*"):
            endian = "Little-Endian" if head[:2] == b"II" else "Big-Endian"
            return DetectedFormat(
                format_name="TIFF",
                mime_type="image/tiff",
                is_supported=True,
                magic_bytes=head[:4],
                magic_hex=magic_hex,
                expected_extensions=[".tif", ".tiff", ".raw", ".cr2", ".nef", ".arw", ".dng"],
            )

        if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
            return DetectedFormat(
                format_name="WEBP",
                mime_type="image/webp",
                is_supported=True,
                magic_bytes=head[:12],
                magic_hex=magic_hex,
                expected_extensions=[".webp"],
            )

        if len(head) >= 12 and head[4:8] == b"ftyp":
            major_brand = head[8:12]
            if major_brand in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1"):
                return DetectedFormat(
                    format_name="HEIC",
                    mime_type="image/heic",
                    is_supported=True,
                    magic_bytes=head[:12],
                    magic_hex=magic_hex,
                    expected_extensions=[".heic", ".heif"],
                )
            if major_brand in (b"avif", b"avis"):
                return DetectedFormat(
                    format_name="AVIF",
                    mime_type="image/avif",
                    is_supported=True,
                    magic_bytes=head[:12],
                    magic_hex=magic_hex,
                    expected_extensions=[".avif"],
                )

        if len(head) >= 6 and (head[:6] == b"GIF87a" or head[:6] == b"GIF89a"):
            return DetectedFormat(
                format_name="GIF",
                mime_type="image/gif",
                is_supported=True,
                magic_bytes=head[:6],
                magic_hex=magic_hex,
                expected_extensions=[".gif"],
            )

        if len(head) >= 2 and head[:2] == b"BM":
            return DetectedFormat(
                format_name="BMP",
                mime_type="image/bmp",
                is_supported=True,
                magic_bytes=head[:2],
                magic_hex=magic_hex,
                expected_extensions=[".bmp"],
            )

        if len(head) >= 4 and head[:4] == b"8BPS":
            return DetectedFormat(
                format_name="PSD",
                mime_type="image/vnd.adobe.photoshop",
                is_supported=True,
                magic_bytes=head[:4],
                magic_hex=magic_hex,
                expected_extensions=[".psd"],
            )

        # Check Office OpenXML / ZIP Packages (PPTX, DOCX, XLSX, ZIP)
        if len(head) >= 4 and head[:4] == b"PK\x03\x04":
            preview_bytes = reader.read_bytes(0, min(reader.size, 65536))
            if b"ppt/" in preview_bytes or b"presentation" in preview_bytes:
                return DetectedFormat(
                    format_name="PPTX",
                    mime_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    is_supported=True,
                    magic_bytes=head[:4],
                    magic_hex=magic_hex,
                    expected_extensions=[".pptx", ".ppsx", ".potx", ".pptm"],
                )
            elif b"word/" in preview_bytes or b"document" in preview_bytes:
                return DetectedFormat(
                    format_name="DOCX",
                    mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    is_supported=True,
                    magic_bytes=head[:4],
                    magic_hex=magic_hex,
                    expected_extensions=[".docx", ".dotx", ".docm"],
                )
            elif b"xl/" in preview_bytes or b"workbook" in preview_bytes:
                return DetectedFormat(
                    format_name="XLSX",
                    mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    is_supported=True,
                    magic_bytes=head[:4],
                    magic_hex=magic_hex,
                    expected_extensions=[".xlsx", ".xltx", ".xlsm"],
                )
            else:
                return DetectedFormat(
                    format_name="ZIP",
                    mime_type="application/zip",
                    is_supported=True,
                    magic_bytes=head[:4],
                    magic_hex=magic_hex,
                    expected_extensions=[".zip", ".odp", ".odt", ".ods", ".apk", ".jar"],
                )

        # Check SVG (XML text)
        try:
            head_str = head.decode("utf-8", errors="ignore").strip().lower()
            if head_str.startswith("<svg") or (head_str.startswith("<?xml") and "<svg" in head_str):
                return DetectedFormat(
                    format_name="SVG",
                    mime_type="image/svg+xml",
                    is_supported=True,
                    magic_bytes=head[:min(len(head), 16)],
                    magic_hex=magic_hex,
                    expected_extensions=[".svg"],
                )
        except Exception:
            pass

        return DetectedFormat(
            format_name="UNKNOWN",
            mime_type="application/octet-stream",
            is_supported=False,
            magic_bytes=head[:8],
            magic_hex=magic_hex,
            expected_extensions=[],
        )

    @classmethod
    def check_extension_mismatch(
        cls, detected: DetectedFormat, file_path: str | Path
    ) -> Optional[Finding]:
        """FR-1.2: Extension/format mismatch must be reported as a finding."""
        ext = Path(file_path).suffix.lower()
        if not ext or not detected.is_supported or not detected.expected_extensions:
            return None

        if ext not in detected.expected_extensions:
            return Finding(
                name="container_extension_mismatch",
                value={
                    "declared_extension": ext,
                    "detected_format": detected.format_name,
                    "expected_extensions": detected.expected_extensions,
                    "magic_hex": detected.magic_hex,
                },
                tier=1,
                extractor="format_detector",
                confidence=Confidence.OBSERVED,
                caveat=None,
                provenance=Provenance(
                    source_layer="sniff",
                    extractor="format_detector",
                    offset=0,
                    length=len(detected.magic_bytes),
                ),
            )
        return None
