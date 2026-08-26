"""Unified artefact extractor for embedded images, metadata streams, payloads, and image crops per FR-4.8."""

from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from imgint.core.source.reader import BoundedReader
from imgint.core.sniff.detector import FormatDetector
from imgint.core.container import create_default_container_registry
from imgint.core.artefact.thumbnail import ThumbnailExtractor
from imgint.core.artefact.preview import PreviewExtractor
from imgint.core.artefact.mpf import MpfExtractor
from imgint.core.artefact.carver import PayloadCarver
from imgint.core.sandbox.process import SandboxRunner


@dataclass
class ExtractedItem:
    item_type: str  # "thumbnail", "preview", "mpf_frame", "payload", "metadata_block", "crop"
    output_path: str
    size_bytes: int
    offset: Optional[int] = None
    sha256: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "item_type": self.item_type,
            "output_path": self.output_path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }
        if self.offset is not None:
            d["offset"] = self.offset
        if self.details:
            d["details"] = self.details
        return d


class ArtefactExtractor:
    """Extracts all embedded, trailing, structural, and cropped artefacts from evidence images."""

    @classmethod
    def extract_all(
        cls,
        file_path: str | Path,
        out_dir: str | Path,
        include_metadata: bool = True,
        include_thumbnail: bool = True,
        include_preview: bool = True,
        include_payload: bool = True,
        crop_coords: Optional[Dict[str, int]] = None,
    ) -> List[ExtractedItem]:
        """Extracts all requested artefacts from the file into out_dir."""
        p = Path(file_path).resolve()
        destination = Path(out_dir).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        extracted: List[ExtractedItem] = []

        reader = BoundedReader(p)
        detected = FormatDetector.detect(reader)
        if not detected.is_supported:
            return extracted

        registry = create_default_container_registry()
        container_reader = registry.get_reader(detected.format_name)
        if not container_reader:
            return extracted

        units, blocks, _ = container_reader.read(reader)
        stem = p.stem

        # 1. Extract IFD1 Thumbnail
        if include_thumbnail:
            for b in blocks:
                if b.kind in ("EXIF", "TIFF_EXIF"):
                    thumb = ThumbnailExtractor.extract_from_exif_block(b)
                    if thumb and thumb.data:
                        ext = "jpg" if thumb.format_type == "JPEG" else "bin"
                        thumb_file = destination / f"{stem}_thumbnail_0x{thumb.offset:X}.{ext}"
                        thumb_file.write_bytes(thumb.data)
                        h = hashlib.sha256(thumb.data).hexdigest()
                        extracted.append(
                            ExtractedItem(
                                item_type="thumbnail",
                                output_path=str(thumb_file),
                                size_bytes=len(thumb.data),
                                offset=thumb.offset,
                                sha256=h,
                                details={"format": thumb.format_type, "source_block": b.kind},
                            )
                        )

        # 2. Extract RAW/TIFF Previews & MPF Secondary Frames
        if include_preview:
            # Check for embedded JPEG preview in RAW / TIFF
            raw_bytes = reader.get_all_bytes()
            prev_data = PreviewExtractor.extract_preview(raw_bytes)
            if prev_data:
                prev_file = destination / f"{stem}_embedded_preview.jpg"
                prev_file.write_bytes(prev_data)
                h = hashlib.sha256(prev_data).hexdigest()
                extracted.append(
                    ExtractedItem(
                        item_type="preview",
                        output_path=str(prev_file),
                        size_bytes=len(prev_data),
                        sha256=h,
                        details={"format": "JPEG"},
                    )
                )

            # MPF Frames
            for b in blocks:
                if b.kind == "MPF":
                    mpf_list = MpfExtractor.extract_from_mpf_block(b)
                    for idx, mpf_img in enumerate(mpf_list):
                        mpf_file = destination / f"{stem}_mpf_frame_{idx + 1}.bin"
                        mpf_file.write_bytes(b.raw_bytes)
                        h = hashlib.sha256(b.raw_bytes).hexdigest()
                        extracted.append(
                            ExtractedItem(
                                item_type="mpf_frame",
                                output_path=str(mpf_file),
                                size_bytes=len(b.raw_bytes),
                                offset=mpf_img.offset,
                                sha256=h,
                                details={"image_type": mpf_img.image_type, "frame_index": mpf_img.index},
                            )
                        )

        # 3. Carve Trailing Payloads (ZIP, RAR, 7z, EXE, ELF, etc.)
        if include_payload:
            carved = PayloadCarver.carve_trailing_payload(reader, units, destination)
            if carved:
                extracted.append(
                    ExtractedItem(
                        item_type="payload",
                        output_path=carved.output_path,
                        size_bytes=carved.size,
                        offset=carved.offset,
                        sha256=carved.sha256,
                        details={"payload_type": carved.payload_type},
                    )
                )

        # 4. Extract Raw Metadata Blocks (EXIF, XMP, IPTC, ICC, C2PA)
        if include_metadata:
            for idx, b in enumerate(blocks):
                kind_clean = b.kind.lower().replace("/", "_")
                ext_map = {
                    "exif": "exif",
                    "tiff_exif": "exif",
                    "xmp": "xmp",
                    "xmp_ext": "xmp",
                    "iptc_8bim": "iptc",
                    "iptc": "iptc",
                    "icc": "icc",
                    "icc_profile": "icc",
                    "c2pa": "c2pa",
                    "jumbf": "jumbf",
                    "png_text": "txt",
                }
                m_ext = ext_map.get(kind_clean, "bin")
                m_file = destination / f"{stem}_meta_{idx + 1}_{kind_clean}_0x{b.offset:X}.{m_ext}"
                m_file.write_bytes(b.raw_bytes)
                h = hashlib.sha256(b.raw_bytes).hexdigest()
                extracted.append(
                    ExtractedItem(
                        item_type="metadata_block",
                        output_path=str(m_file),
                        size_bytes=len(b.raw_bytes),
                        offset=b.offset,
                        sha256=h,
                        details={"kind": b.kind, "source_unit": b.source_unit},
                    )
                )

        # 5. Extract Cropped Region at -x, -y Coordinates
        if crop_coords and "x" in crop_coords and "y" in crop_coords:
            cx = crop_coords["x"]
            cy = crop_coords["y"]
            cw = crop_coords.get("width", 200)
            ch = crop_coords.get("height", 200)
            crop_file = destination / f"{stem}_crop_x{cx}_y{cy}_{cw}x{ch}.png"

            res = SandboxRunner.run_decode_tasks(
                p,
                tasks=["crop", "pixel_at_xy"],
                extra_params={"x": cx, "y": cy, "width": cw, "height": ch, "crop_out_path": str(crop_file)},
            )
            if res.get("success") and "tasks" in res:
                crop_info = res["tasks"].get("crop", {})
                pixel_info = res["tasks"].get("pixel_at_xy", {})
                if crop_file.exists():
                    crop_bytes = crop_file.read_bytes()
                    h = hashlib.sha256(crop_bytes).hexdigest()
                    extracted.append(
                        ExtractedItem(
                            item_type="crop",
                            output_path=str(crop_file),
                            size_bytes=len(crop_bytes),
                            sha256=h,
                            details={
                                "x": cx,
                                "y": cy,
                                "width": crop_info.get("width", cw),
                                "height": crop_info.get("height", ch),
                                "box": crop_info.get("box", []),
                                "pixel_color": pixel_info.get("hex"),
                            },
                        )
                    )

        return extracted
