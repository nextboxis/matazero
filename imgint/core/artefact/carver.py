"""Automatic payload carver for trailing data, polyglots, and embedded archives per FR-4.5."""

from __future__ import annotations
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from imgint.core.source.reader import BoundedReader
from imgint.core.model.record import StructuralUnit


@dataclass
class CarvedPayload:
    source_file: str
    output_path: str
    offset: int
    size: int
    payload_type: str
    sha256: str


class PayloadCarver:
    """Carves hidden or trailing payload archives from container streams."""

    PAYLOAD_EXTENSIONS = {
        "ZIP Archive": "zip",
        "RAR Archive": "rar",
        "7z Archive": "7z",
        "Windows Executable (PE)": "exe",
        "Linux ELF Executable": "elf",
        "GZIP Archive": "gz",
        "BZIP2 Archive": "bz2",
    }

    @classmethod
    def identify_type(cls, data: bytes) -> tuple[str, str]:
        if data.startswith(b"PK\x03\x04"):
            return "ZIP Archive", "zip"
        elif data.startswith(b"Rar!\x1a\x07"):
            return "RAR Archive", "rar"
        elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7z Archive", "7z"
        elif data.startswith(b"MZ"):
            return "Windows Executable (PE)", "exe"
        elif data.startswith(b"\x7fELF"):
            return "Linux ELF Executable", "elf"
        elif data.startswith(b"\x1f\x8b"):
            return "GZIP Archive", "gz"
        elif data.startswith(b"BZh"):
            return "BZIP2 Archive", "bz2"
        return "Unknown Binary Payload", "bin"

    @classmethod
    def carve_trailing_payload(
        cls,
        reader: BoundedReader,
        units: List[StructuralUnit],
        out_dir: Path | str,
    ) -> Optional[CarvedPayload]:
        """Check for trailing data past final EOI/IEND and carve out to out_dir."""
        if not units:
            return None

        # Check if there is a TRAILING_DATA unit
        trailing_unit = next((u for u in units if u.name == "TRAILING_DATA"), None)
        if trailing_unit:
            terminal_offset = trailing_unit.offset
            trailing_len = trailing_unit.length
        else:
            # Find non-trailing terminal unit (e.g. EOI, IEND, TRAILER)
            non_trailing = [u for u in units if u.name != "TRAILING_DATA"]
            if not non_trailing:
                return None
            last_unit = max(non_trailing, key=lambda u: u.offset + u.length)
            terminal_offset = last_unit.offset + last_unit.length
            trailing_len = reader.size - terminal_offset

        if trailing_len <= 0 or terminal_offset >= reader.size:
            return None

        trailing_bytes = reader.read_bytes(terminal_offset, trailing_len)
        p_name, p_ext = cls.identify_type(trailing_bytes)

        out_directory = Path(out_dir)
        out_directory.mkdir(parents=True, exist_ok=True)

        source_stem = reader.path.stem if reader.path else "evidence"
        out_file = out_directory / f"{source_stem}_carved_0x{terminal_offset:X}.{p_ext}"

        with open(out_file, "wb") as f:
            f.write(trailing_bytes)

        payload_hash = hashlib.sha256(trailing_bytes).hexdigest()

        return CarvedPayload(
            source_file=str(reader.path) if reader.path else "memory_stream",
            output_path=str(out_file),
            offset=terminal_offset,
            size=trailing_len,
            payload_type=p_name,
            sha256=payload_hash,
        )
