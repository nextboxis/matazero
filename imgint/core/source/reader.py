"""Bounded, windowed binary reader with strict bounds checking per SRD NFR-1.4 - NFR-1.6."""

from __future__ import annotations
import struct
from pathlib import Path
from typing import Optional, Union


class SourceBoundsError(Exception):
    """Raised when an out-of-bounds or oversized read is attempted."""
    pass


class BoundedReader:
    """Safely reads slices of a file or byte buffer under strict bounds and allocation limits."""

    def __init__(
        self,
        source: Union[bytes, str, Path],
        max_read_size: int = 16 * 1024 * 1024,  # 16 MB max per chunk
        max_units: int = 4096,
        max_depth: int = 16,
    ):
        if isinstance(source, bytes):
            self._buffer = source
            self._path: Optional[Path] = None
            self._size = len(source)
        else:
            self._path = Path(source)
            self._size = self._path.stat().st_size
            with open(self._path, "rb") as f:
                self._buffer = f.read()
        self.max_read_size = max_read_size
        self.max_units = max_units
        self.max_depth = max_depth
        self.unit_count = 0
        self.current_depth = 0

    @property
    def size(self) -> int:
        return self._size

    @property
    def path(self) -> Optional[Path]:
        return self._path

    def check_unit_budget(self) -> None:
        self.unit_count += 1
        if self.unit_count > self.max_units:
            raise SourceBoundsError(
                f"Exceeded maximum structural unit count ({self.max_units}). Possible container recursion bomb."
            )

    def enter_depth(self) -> None:
        self.current_depth += 1
        if self.current_depth > self.max_depth:
            raise SourceBoundsError(
                f"Exceeded maximum container recursion depth ({self.max_depth})."
            )

    def exit_depth(self) -> None:
        if self.current_depth > 0:
            self.current_depth -= 1

    def can_read(self, length: int, offset: Optional[int] = None) -> bool:
        if length < 0:
            return False
        off = offset if offset is not None else 0
        return off + length <= self._size

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise SourceBoundsError(f"Negative offset ({offset}) or length ({length})")
        if offset + length > self._size:
            raise SourceBoundsError(
                f"Read out of bounds: offset {offset} + length {length} > size {self._size}"
            )
        if length > self.max_read_size:
            raise SourceBoundsError(
                f"Attempted allocation {length} exceeds maximum safety cap {self.max_read_size}"
            )
        return self._buffer[offset : offset + length]

    def read_u8(self, offset: int) -> int:
        b = self.read_bytes(offset, 1)
        return b[0]

    def read_u16_be(self, offset: int) -> int:
        b = self.read_bytes(offset, 2)
        return struct.unpack(">H", b)[0]

    def read_u16_le(self, offset: int) -> int:
        b = self.read_bytes(offset, 2)
        return struct.unpack("<H", b)[0]

    def read_u32_be(self, offset: int) -> int:
        b = self.read_bytes(offset, 4)
        return struct.unpack(">I", b)[0]

    def read_u32_le(self, offset: int) -> int:
        b = self.read_bytes(offset, 4)
        return struct.unpack("<I", b)[0]

    def slice(self, offset: int, length: Optional[int] = None) -> BoundedReader:
        if length is None:
            length = self._size - offset
        data = self.read_bytes(offset, length)
        return BoundedReader(
            data,
            max_read_size=self.max_read_size,
            max_units=self.max_units,
            max_depth=self.max_depth,
        )

    def find(self, sub: bytes, start: int = 0, end: Optional[int] = None) -> int:
        if end is None:
            end = self._size
        return self._buffer.find(sub, start, end)

    def get_all_bytes(self) -> bytes:
        return self._buffer
