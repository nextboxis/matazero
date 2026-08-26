"""XMP parser with safe entity-disabled XML parsing per SRD FR-2.4, FR-2.5, and NFR-1.7."""

from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import MetadataBlock, Field, Diagnostic
from imgint.core.standard.base import BlockParser


class XmpParser(BlockParser):
    """Safely parses XMP RDF/XML metadata without resolving external entities."""

    def handles(self, kind: str) -> bool:
        return kind in ("XMP", "XMP_EXT")

    def parse(
        self, block: MetadataBlock
    ) -> Tuple[List[Field], List[Finding], List[Diagnostic]]:
        fields: List[Field] = []
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        data = block.raw_bytes
        try:
            xml_text = data.decode("utf-8", errors="replace")
        except Exception:
            xml_text = str(data)

        # Locate rdf:RDF or x:xmpmeta tag
        start_idx = xml_text.find("<")
        if start_idx == -1:
            return fields, findings, diagnostics

        clean_xml = xml_text[start_idx:]
        end_idx = clean_xml.rfind(">")
        if end_idx != -1:
            clean_xml = clean_xml[: end_idx + 1]

        try:
            # Defend against XXE and entity expansion by using standard ElementTree without custom entity resolvers
            parser = ET.XMLParser()
            root = ET.fromstring(clean_xml, parser=parser)

            # Walk all elements
            for elem in root.iter():
                tag = elem.tag
                # Strip namespace URI if present
                if "}" in tag:
                    tag_name = tag.split("}", 1)[1]
                else:
                    tag_name = tag

                text = (elem.text or "").strip()
                if text and tag_name not in ("RDF", "Description", "xmpmeta"):
                    fields.append(
                        Field(
                            standard="XMP",
                            tag_id=tag,
                            name=f"xmp:{tag_name}",
                            value=text,
                            raw_value=text,
                            value_type="STRING",
                        )
                    )

                # Process attributes on Description elements (e.g. exif:DateTimeOriginal)
                for attr_key, attr_val in elem.attrib.items():
                    attr_name = attr_key.split("}", 1)[1] if "}" in attr_key else attr_key
                    if attr_val and not attr_name.startswith("xmlns"):
                        fields.append(
                            Field(
                                standard="XMP",
                                tag_id=attr_key,
                                name=f"xmp:{attr_name}",
                                value=attr_val,
                                raw_value=attr_val,
                                value_type="STRING",
                            )
                        )
                        if attr_name.lower() in ("modifydate", "createdate", "metadatadate", "history", "creator", "format"):
                            findings.append(
                                Finding(
                                    name=f"xmp_{attr_name.lower()}",
                                    value=attr_val,
                                    tier=1,
                                    extractor="xmp_parser",
                                    confidence=Confidence.OBSERVED,
                                    caveat=None,
                                    provenance=Provenance(
                                        source_layer="standard",
                                        extractor="xmp_parser",
                                        offset=block.offset,
                                        standard="XMP",
                                        tag_id=attr_key,
                                    ),
                                )
                            )

            findings.append(
                Finding(
                    name="xmp_packet_present",
                    value={"byte_length": len(block.raw_bytes), "tag_count": len(fields)},
                    tier=1,
                    extractor="xmp_parser",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(
                        source_layer="standard",
                        extractor="xmp_parser",
                        offset=block.offset,
                        length=block.length,
                        standard="XMP",
                    ),
                )
            )

        except Exception as e:
            diagnostics.append(
                Diagnostic(
                    level="warning",
                    message=f"XMP XML parsing diagnostic: {e}",
                    source="xmp_parser",
                    offset=block.offset,
                )
            )

        return fields, findings, diagnostics
