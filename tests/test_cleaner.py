import struct
from pathlib import Path
import pytest
from imgint.core.clean.cleaner import MetadataCleaner

def test_clean_jpeg():
    data = bytearray(b"\xFF\xD8")
    data.extend(b"\xFF\xE1\x00\x06EXIF")
    data.extend(b"\xFF\xDB\x00\x05DQT")
    data.extend(b"\xFF\xDA\x00\x02SOSDATA\xFF\xD9")
    
    cleaned = MetadataCleaner._clean_jpeg(bytes(data))
    
    assert b"EXIF" not in cleaned
    assert b"DQT" in cleaned
    assert b"SOSDATA\xFF\xD9" in cleaned

def test_clean_png():
    data = bytearray(b"\x89PNG\r\n\x1a\n")
    data.extend(struct.pack(">I", 4) + b"IHDRDATA1234")
    data.extend(struct.pack(">I", 4) + b"tEXtDATA1234")
    data.extend(struct.pack(">I", 4) + b"IENDDATA1234")
    
    cleaned = MetadataCleaner._clean_png(bytes(data))
    
    assert b"IHDR" in cleaned
    assert b"IEND" in cleaned
    assert b"tEXt" not in cleaned

def test_clean_webp():
    payload = bytearray(b"VP8 ")
    payload.extend(struct.pack("<I", 4) + b"DATA")
    
    exif = bytearray(b"EXIF")
    exif.extend(struct.pack("<I", 4) + b"META")
    
    total_len = 4 + len(payload) + len(exif)
    data = bytearray(b"RIFF")
    data.extend(struct.pack("<I", total_len))
    data.extend(b"WEBP")
    data.extend(payload)
    data.extend(exif)
    
    cleaned = MetadataCleaner._clean_webp(bytes(data))
    
    assert b"VP8 " in cleaned
    assert b"EXIF" not in cleaned
