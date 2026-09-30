"""Tests for BoundedReader memory safety, bounds checks, and mmap."""

from pathlib import Path
import pytest

from imgint.core.source.reader import BoundedReader, SourceBoundsError


def test_bounded_reader_bytes_in_memory():
    data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"
    reader = BoundedReader(data, max_read_size=1024)

    assert reader.size == 10
    assert reader.can_read(5, offset=0) is True
    assert reader.can_read(11, offset=0) is False
    assert reader.read_bytes(0, 4) == b"\x00\x01\x02\x03"
    assert reader.read_u8(0) == 0
    assert reader.read_u8(9) == 9
    assert reader.read_u16_be(0) == 0x0001
    assert reader.read_u16_le(0) == 0x0100
    assert reader.read_u32_be(0) == 0x00010203
    assert reader.read_u32_le(0) == 0x03020100


def test_bounded_reader_file_mmap(tmp_path: Path):
    test_file = tmp_path / "sample.bin"
    payload = b"MATAZERO_FORENSICS_TEST_PAYLOAD" * 100
    test_file.write_bytes(payload)

    with BoundedReader(test_file) as reader:
        assert reader.size == len(payload)
        assert reader.read_bytes(0, 8) == b"MATAZERO"
        idx = reader.find(b"_TEST_")
        assert idx != -1
        assert reader.slice(idx, 6).read_bytes(0, 6) == b"_TEST_"


def test_bounded_reader_bounds_violations(tmp_path: Path):
    test_file = tmp_path / "small.bin"
    test_file.write_bytes(b"12345678")

    with BoundedReader(test_file, max_read_size=4) as reader:
        with pytest.raises(SourceBoundsError):
            reader.read_bytes(10, 2)

        with pytest.raises(SourceBoundsError):
            reader.read_bytes(0, 100)

        with pytest.raises(SourceBoundsError):
            reader.read_bytes(0, 6)

        with pytest.raises(SourceBoundsError):
            reader.read_bytes(-1, 2)


def test_bounded_reader_unit_and_depth_limits():
    reader = BoundedReader(b"A" * 64, max_units=3, max_depth=2)

    reader.check_unit_budget()
    reader.check_unit_budget()
    reader.check_unit_budget()
    with pytest.raises(SourceBoundsError):
        reader.check_unit_budget()

    reader.enter_depth()
    reader.enter_depth()
    with pytest.raises(SourceBoundsError):
        reader.enter_depth()
    reader.exit_depth()
    reader.enter_depth()
