"""Metadata standard parsers and registry."""

from imgint.core.standard.base import BlockParser
from imgint.core.standard.registry import StandardRegistry
from imgint.core.standard.exif import ExifParser
from imgint.core.standard.xmp import XmpParser
from imgint.core.standard.iptc import IptcParser
from imgint.core.standard.icc import IccParser
from imgint.core.standard.c2pa import C2paParser
from imgint.core.standard.png_native import PngNativeParser
from imgint.core.standard.office_props import OfficePropertiesParser


def create_default_standard_registry() -> StandardRegistry:
    reg = StandardRegistry()
    reg.register(ExifParser())
    reg.register(XmpParser())
    reg.register(IptcParser())
    reg.register(IccParser())
    reg.register(C2paParser())
    reg.register(PngNativeParser())
    reg.register(OfficePropertiesParser())
    return reg


__all__ = [
    "BlockParser",
    "StandardRegistry",
    "ExifParser",
    "XmpParser",
    "IptcParser",
    "IccParser",
    "C2paParser",
    "PngNativeParser",
    "OfficePropertiesParser",
    "create_default_standard_registry",
]
