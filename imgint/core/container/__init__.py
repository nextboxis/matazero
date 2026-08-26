"""Container readers and registry."""

from imgint.core.container.base import ContainerReader
from imgint.core.container.registry import ContainerRegistry
from imgint.core.container.jpeg import JpegContainerReader
from imgint.core.container.png import PngContainerReader
from imgint.core.container.tiff import TiffContainerReader
from imgint.core.container.riff import RiffContainerReader
from imgint.core.container.bmff import BmffContainerReader
from imgint.core.container.gif import GifContainerReader


def create_default_container_registry() -> ContainerRegistry:
    reg = ContainerRegistry()
    reg.register(JpegContainerReader())
    reg.register(PngContainerReader())
    reg.register(TiffContainerReader())
    reg.register(RiffContainerReader())
    reg.register(BmffContainerReader())
    reg.register(GifContainerReader())
    return reg


__all__ = [
    "ContainerReader",
    "ContainerRegistry",
    "JpegContainerReader",
    "PngContainerReader",
    "TiffContainerReader",
    "RiffContainerReader",
    "BmffContainerReader",
    "GifContainerReader",
    "create_default_container_registry",
]
