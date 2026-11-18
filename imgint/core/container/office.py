"""PowerPoint (PPTX), Word (DOCX), and Excel (XLSX) OpenXML Container Reader.

Parses presentation packages, enumerates all embedded slide images, extracts document
metadata (author, creation/modification dates, revisions, software application),
and discovers hidden slides and speaker notes.
"""

from __future__ import annotations
import io
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from imgint.core.container.base import ContainerReader
from imgint.core.model.record import StructuralUnit, MetadataBlock, Diagnostic
from imgint.core.source.reader import BoundedReader, SourceBoundsError


class OfficeContainerReader(ContainerReader):
    """Parses Office OpenXML packages (.pptx, .docx, .xlsx) for embedded images and metadata."""

    MAX_ZIP_ENTRY_BYTES = 16 * 1024 * 1024
    MAX_XML_ENTRY_BYTES = 2 * 1024 * 1024
    MAX_TOTAL_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
    MAX_COMPRESSION_RATIO = 100.0

    @staticmethod
    def _validate_safe_xml(raw_xml: bytes) -> None:
        head_upper = raw_xml[:4096].decode("utf-8", errors="ignore").upper()
        if "<!DOCTYPE" in head_upper or "<!ENTITY" in head_upper:
            raise ValueError("Unsafe XML DTD/Entity declaration rejected (XXE/Billion Laughs protection)")

    def handles(self, format_name: str) -> bool:
        return format_name in ("PPTX", "DOCX", "XLSX", "OFFICE_XML")

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        raw_data = reader.read_bytes(0, min(reader.size, reader.max_read_size))

        try:
            with zipfile.ZipFile(io.BytesIO(raw_data), "r") as zf:
                infolist = zf.infolist()

                media_files = []
                notes_files = []
                slides_files = []
                total_uncompressed = 0

                def _safe_zip_read(info: zipfile.ZipInfo, max_bytes: int) -> bytes:
                    nonlocal total_uncompressed
                    reader.check_unit_budget()
                    if ".." in Path(info.filename).parts or info.filename.startswith(("/", "\\")):
                        raise SourceBoundsError(f"Zip Slip path traversal detected in entry: {info.filename}")
                    if info.file_size > max_bytes:
                        raise SourceBoundsError(
                            f"ZIP entry '{info.filename}' uncompressed size ({info.file_size:,} B) exceeds safety limit ({max_bytes:,} B)."
                        )
                    if info.compress_size > 0 and info.file_size > 65536:
                        ratio = info.file_size / max(1, info.compress_size)
                        if ratio > self.MAX_COMPRESSION_RATIO:
                            raise SourceBoundsError(
                                f"Potential ZIP decompression bomb in '{info.filename}' (compression ratio {ratio:.1f}x > {self.MAX_COMPRESSION_RATIO}x)."
                            )
                    if total_uncompressed + info.file_size > self.MAX_TOTAL_UNCOMPRESSED_BYTES:
                        raise SourceBoundsError(
                            f"Cumulative uncompressed Office package size exceeds safety cap ({self.MAX_TOTAL_UNCOMPRESSED_BYTES:,} B)."
                        )
                    with zf.open(info, "r") as zf_entry:
                        data = zf_entry.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        raise SourceBoundsError(f"ZIP entry '{info.filename}' exceeded {max_bytes:,} B during stream read.")
                    total_uncompressed += len(data)
                    return data

                for info in infolist:
                    fname = info.filename
                    if fname.startswith(("ppt/media/", "word/media/", "xl/media/")):
                        media_files.append(info)
                        img_bytes = _safe_zip_read(info, self.MAX_ZIP_ENTRY_BYTES)
                        safe_media_name = Path(fname).name
                        units.append(
                            StructuralUnit(
                                name=f"EMBEDDED_IMAGE:{safe_media_name}",
                                offset=info.header_offset,
                                length=info.file_size,
                                data_offset=info.header_offset,
                                data_length=info.compress_size,
                                description=f"Embedded presentation image ({safe_media_name}, {info.file_size:,} bytes)",
                                payload=img_bytes[:4096],
                            )
                        )
                        blocks.append(
                            MetadataBlock(
                                kind="EMBEDDED_IMAGE",
                                offset=info.header_offset,
                                length=info.file_size,
                                raw_bytes=img_bytes,
                                source_unit=safe_media_name,
                            )
                        )
                    elif fname.startswith("ppt/notesSlides/"):
                        notes_files.append(info)
                    elif fname.startswith("ppt/slides/"):
                        slides_files.append(info)

                units.append(
                    StructuralUnit(
                        name="OFFICE_MEDIA_COLLECTION",
                        offset=0,
                        length=len(raw_data),
                        data_offset=0,
                        data_length=sum(m.file_size for m in media_files),
                        description=f"Collection of {len(media_files)} embedded image/media assets inside presentation",
                    )
                )

                if "docProps/core.xml" in zf.namelist():
                    core_bytes = _safe_zip_read(zf.getinfo("docProps/core.xml"), self.MAX_XML_ENTRY_BYTES)
                    blocks.append(
                        MetadataBlock(
                            kind="OFFICE_CORE_PROPERTIES",
                            offset=0,
                            length=len(core_bytes),
                            raw_bytes=core_bytes,
                            source_unit="docProps/core.xml",
                        )
                    )
                    self._parse_core_properties(core_bytes, units)

                if "docProps/app.xml" in zf.namelist():
                    app_bytes = _safe_zip_read(zf.getinfo("docProps/app.xml"), self.MAX_XML_ENTRY_BYTES)
                    blocks.append(
                        MetadataBlock(
                            kind="OFFICE_APP_PROPERTIES",
                            offset=0,
                            length=len(app_bytes),
                            raw_bytes=app_bytes,
                            source_unit="docProps/app.xml",
                        )
                    )
                    self._parse_app_properties(app_bytes, units)

                for n_info in notes_files:
                    try:
                        n_bytes = _safe_zip_read(n_info, self.MAX_XML_ENTRY_BYTES)
                        self._validate_safe_xml(n_bytes)
                        root = ET.fromstring(n_bytes)
                        texts = [elem.text for elem in root.iter() if elem.tag.endswith("}t") and elem.text]
                        if texts:
                            notes_text = " ".join(texts).strip()
                            if notes_text:
                                blocks.append(
                                    MetadataBlock(
                                        kind="OFFICE_SPEAKER_NOTES",
                                        offset=n_info.header_offset,
                                        length=len(n_bytes),
                                        raw_bytes=notes_text.encode("utf-8"),
                                        source_unit=Path(n_info.filename).name,
                                    )
                                )
                    except Exception:
                        pass

        except Exception as e:
            diagnostics.append(
                Diagnostic(level="warning", message=f"Office package read error: {e}", source="office_reader", offset=0)
            )

        return units, blocks, diagnostics

    def _parse_core_properties(self, raw_xml: bytes, units: List[StructuralUnit]) -> None:
        try:
            self._validate_safe_xml(raw_xml)
            root = ET.fromstring(raw_xml)
            props = {}
            for child in root:
                tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child.text:
                    props[tag_name] = child.text.strip()

            units.append(
                StructuralUnit(
                    name="DOCPROPS_CORE",
                    offset=0,
                    length=len(raw_xml),
                    data_offset=0,
                    data_length=len(raw_xml),
                    description=f"Core Properties: Creator={props.get('creator', 'Unknown')}, Modified={props.get('lastModifiedBy', 'Unknown')}",
                )
            )
        except Exception:
            pass

    def _parse_app_properties(self, raw_xml: bytes, units: List[StructuralUnit]) -> None:
        try:
            self._validate_safe_xml(raw_xml)
            root = ET.fromstring(raw_xml)
            props = {}
            for child in root:
                tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child.text:
                    props[tag_name] = child.text.strip()

            slides = props.get("Slides", "0")
            hidden = props.get("HiddenSlides", "0")
            app_name = props.get("Application", "Unknown")
            units.append(
                StructuralUnit(
                    name="DOCPROPS_APP",
                    offset=0,
                    length=len(raw_xml),
                    data_offset=0,
                    data_length=len(raw_xml),
                    description=f"App Properties: App={app_name}, Slides={slides} (Hidden={hidden})",
                )
            )
        except Exception:
            pass
