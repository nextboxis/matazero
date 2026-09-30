from __future__ import annotations
from typing import Optional

import click
from rich.console import Console

from imgint.core.motion import MotionPhotoDetector, MotionPhotoCarver, MotionPhotoRenderer

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.command("motion")
@click.argument("target", type=click.Path(exists=True))
@click.option("-c", "--carve", is_flag=True, help="Carve embedded video stream to disk")
@click.option("-o", "--out", "out_path", default=None, type=click.Path(), help="Output path/directory for carved video")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def motion(
    target: str,
    carve: bool,
    out_path: Optional[str],
    out_fmt: str,
) -> None:
    """Detect and carve embedded MP4/HEVC video streams from Samsung/Pixel/Apple motion photos."""
    if carve:
        info = MotionPhotoCarver.carve(target, output_file=out_path if out_path and out_path.endswith((".mp4", ".mov")) else None, output_dir=out_path)
    else:
        info = MotionPhotoDetector.detect(target)

    if out_fmt == "json":
        print(MotionPhotoRenderer.render_json(info))
    else:
        MotionPhotoRenderer.render_terminal(info, console)
