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

    def handles(self, format_name: str) -> bool:
        return format_name in ("PPTX", "DOCX", "XLSX", "OFFICE_XML")

    def read(
        self, reader: BoundedReader
    ) -> Tuple[List[StructuralUnit], List[MetadataBlock], List[Diagnostic]]:
        units: List[StructuralUnit] = []
        blocks: List[MetadataBlock] = []
        diagnostics: List[Diagnostic] = []

        raw_data = reader.read_bytes(0, min(reader.size, 100 * 1024 * 1024))  # Up to 100MB

        try:
            with zipfile.ZipFile(io.BytesIO(raw_data), "r") as zf:
                infolist = zf.infolist()

                media_files = []
                notes_files = []
                slides_files = []

                for info in infolist:
                    fname = info.filename
                    # Check embedded media
                    if fname.startswith(("ppt/media/", "word/media/", "xl/media/")):
                        media_files.append(info)
                        img_bytes = zf.read(fname)
                        units.append(
                            StructuralUnit(
                                name=f"EMBEDDED_IMAGE:{Path(fname).name}",
                                offset=info.header_offset,
                                length=info.file_size,
                                data_offset=info.header_offset,
                                data_length=info.compress_size,
                                description=f"Embedded presentation image ({Path(fname).name}, {info.file_size:,} bytes)",
                                payload=img_bytes[:4096],
                            )
                        )
                        blocks.append(
                            MetadataBlock(
                                kind="EMBEDDED_IMAGE",
                                offset=info.header_offset,
                                length=info.file_size,
                                raw_bytes=img_bytes,
                                source_unit=fname,
                            )
                        )
                    elif fname.startswith("ppt/notesSlides/"):
                        notes_files.append(info)
                    elif fname.startswith("ppt/slides/"):
                        slides_files.append(info)

                # Summary unit of all embedded media
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

                # Parse docProps/core.xml (Dublin Core Metadata)
                if "docProps/core.xml" in zf.namelist():
                    core_bytes = zf.read("docProps/core.xml")
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

                # Parse docProps/app.xml (Extended Application Properties)
                if "docProps/app.xml" in zf.namelist():
                    app_bytes = zf.read("docProps/app.xml")
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

                # Parse speaker notes for hidden text
                for n_info in notes_files:
                    try:
                        n_bytes = zf.read(n_info.filename)
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
                                        source_unit=n_info.filename,
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
