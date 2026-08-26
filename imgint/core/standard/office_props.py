"""Office OpenXML (PPTX, DOCX, XLSX) Core & App Properties Standard Parser.

Extracts Dublin Core document metadata (Author, LastModifiedBy, Creation Date,
Modification Date, Title) and extended Application Properties (Slide Count,
Hidden Slides, Application Name, Company) as forensic Field and Finding records.
"""

from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import List, Tuple
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.standard.base import BlockParser


class OfficePropertiesParser(BlockParser):
    """Parses Office OpenXML metadata blocks into structured fields and findings."""

    def handles(self, block_kind: str) -> bool:
        return block_kind in (
            "OFFICE_CORE_PROPERTIES",
            "OFFICE_APP_PROPERTIES",
            "OFFICE_SPEAKER_NOTES",
            "EMBEDDED_IMAGE",
        )

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        if block.kind == "OFFICE_CORE_PROPERTIES":
            self._parse_core_xml(block, fields, findings)
        elif block.kind == "OFFICE_APP_PROPERTIES":
            self._parse_app_xml(block, fields, findings)
        elif block.kind == "OFFICE_SPEAKER_NOTES":
            try:
                note_text = block.raw_bytes.decode("utf-8", errors="replace").strip()
                if note_text:
                    fields.append(
                        Field(
                            standard="OFFICE_XML",
                            name=f"SpeakerNotes:{block.source_unit or 'Notes'}",
                            value=note_text[:200] + ("..." if len(note_text) > 200 else ""),
                            raw_value=note_text,
                            value_type="string",
                            offset=block.offset,
                            value_offset=block.offset,
                            length=block.length,
                        )
                    )
            except Exception:
                pass
        elif block.kind == "EMBEDDED_IMAGE":
            img_name = block.source_unit or "Embedded Image"
            fields.append(
                Field(
                    standard="OFFICE_XML",
                    name=f"EmbeddedImage:{img_name}",
                    value=f"{block.length:,} bytes",
                    raw_value=block.length,
                    value_type="integer",
                    offset=block.offset,
                    value_offset=block.offset,
                    length=block.length,
                )
            )
            # Recursively inspect embedded image metadata (EXIF, GPS, camera model)
            if block.raw_bytes:
                try:
                    from imgint.core.source.reader import BoundedReader
                    from imgint.core.sniff.detector import FormatDetector
                    from imgint.core.container import create_default_container_registry
                    from imgint.core.standard.exif import ExifParser
                    from imgint.core.standard.xmp import XmpParser
                    from imgint.core.standard.iptc import IptcParser

                    sub_r = BoundedReader(block.raw_bytes)
                    sub_det = FormatDetector.detect(sub_r)
                    if sub_det.is_supported and sub_det.format_name in ("JPEG", "PNG", "TIFF", "WEBP"):
                        sub_reg = create_default_container_registry()
                        sub_creader = sub_reg.get_reader(sub_det.format_name)
                        if sub_creader:
                            _, sub_blocks, _ = sub_creader.read(sub_r)
                            parsers = [ExifParser(), XmpParser(), IptcParser()]
                            for sb in sub_blocks:
                                for p in parsers:
                                    if p.handles(sb.kind):
                                        sub_fields, sub_fnds, _ = p.parse(sb)
                                        fields.extend(sub_fields)
                                        findings.extend(sub_fnds)
                except Exception:
                    pass

        return fields, findings, diagnostics

    def _parse_core_xml(self, block: MetadataBlock, fields: List[Field], findings: List[Finding]) -> None:
        try:
            root = ET.fromstring(block.raw_bytes)
            tag_map = {
                "creator": ("Author", "Author / Creator"),
                "lastModifiedBy": ("LastModifiedBy", "Last Modified By"),
                "created": ("DateTimeOriginal", "Creation Timestamp"),
                "modified": ("DateTime", "Modification Timestamp"),
                "title": ("Title", "Document Title"),
                "subject": ("Subject", "Document Subject"),
                "revision": ("Revision", "Document Revision Number"),
            }

            extracted: dict = {}
            for child in root:
                tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if tag_name in tag_map and child.text and child.text.strip():
                    f_name, desc = tag_map[tag_name]
                    val = child.text.strip()
                    extracted[f_name] = val
                    fields.append(
                        Field(
                            standard="OFFICE_XML",
                            name=f_name,
                            value=val,
                            raw_value=val,
                            value_type="string",
                            offset=block.offset,
                            value_offset=block.offset,
                            length=block.length,
                        )
                    )

            if extracted:
                findings.append(
                    Finding(
                        name="office_document_metadata",
                        value=extracted,
                        tier=1,
                        extractor="office_properties_parser",
                        confidence=Confidence.OBSERVED,
                        caveat=None,
                        provenance=Provenance(source_layer="metadata_block", extractor="office_properties_parser", offset=block.offset),
                    )
                )
        except Exception:
            pass

    def _parse_app_xml(self, block: MetadataBlock, fields: List[Field], findings: List[Finding]) -> None:
        try:
            root = ET.fromstring(block.raw_bytes)
            tag_map = {
                "Application": "Application",
                "AppVersion": "AppVersion",
                "Company": "Company",
                "Slides": "SlideCount",
                "HiddenSlides": "HiddenSlideCount",
                "Notes": "NotesCount",
                "TotalTime": "TotalEditTimeMinutes",
            }

            extracted: dict = {}
            for child in root:
                tag_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if tag_name in tag_map and child.text and child.text.strip():
                    f_name = tag_map[tag_name]
                    val = child.text.strip()
                    extracted[f_name] = val
                    fields.append(
                        Field(
                            standard="OFFICE_XML",
                            name=f_name,
                            value=val,
                            raw_value=val,
                            value_type="string",
                            offset=block.offset,
                            value_offset=block.offset,
                            length=block.length,
                        )
                    )

            if extracted:
                findings.append(
                    Finding(
                        name="office_application_properties",
                        value=extracted,
                        tier=1,
                        extractor="office_properties_parser",
                        confidence=Confidence.OBSERVED,
                        caveat=None,
                        provenance=Provenance(source_layer="metadata_block", extractor="office_properties_parser", offset=block.offset),
                    )
                )
        except Exception:
            pass
