"""Renderer for motion photo analysis and carving results."""

from __future__ import annotations
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from imgint.core.motion.detector import MotionPhotoInfo


class MotionPhotoRenderer:
    """Renders MotionPhotoInfo as Rich terminal panels or JSON."""

    @classmethod
    def render_terminal(cls, info: MotionPhotoInfo, console: Console) -> None:
        file_name = Path(info.file_path).name

        panel_content = Text()
        panel_content.append(f"Target Evidence:     ", style="dim")
        panel_content.append(f"{file_name}\n", style="bold cyan")
        panel_content.append(f"Motion Photo Status: ", style="dim")

        if info.is_motion_photo:
            panel_content.append(f"[EMBEDDED VIDEO DETECTED]\n", style="bold green")
            panel_content.append(f"Motion Container:    ", style="dim")
            panel_content.append(f"{info.motion_type}\n", style="yellow")
            panel_content.append(f"Video Byte Offset:   ", style="dim")
            panel_content.append(f"0x{info.video_offset:08X} ({info.video_offset:,} bytes)\n", style="white")
            panel_content.append(f"Video Payload Size:  ", style="dim")
            panel_content.append(f"{info.video_size_bytes:,} bytes\n", style="white")
            if info.video_codec_brand:
                panel_content.append(f"Container Brand:     ", style="dim")
                panel_content.append(f"{info.video_codec_brand}\n", style="magenta")
            if info.presentation_timestamp_us:
                panel_content.append(f"Still Keyframe PTS:  ", style="dim")
                panel_content.append(f"{info.presentation_timestamp_us:,} µs\n", style="cyan")
            if info.carved_path:
                panel_content.append(f"\n[OK] Carved Video File: ", style="bold green")
                panel_content.append(f"{info.carved_path}\n", style="bold white")
        else:
            panel_content.append(f"[NO EMBEDDED MOTION STREAM]\n", style="dim")

        console.print(Panel(panel_content, title="[bold]matazero Motion & Live Photo Forensic Analyzer[/bold]", border_style="cyan"))

    @classmethod
    def render_json(cls, info: MotionPhotoInfo) -> str:
        return json.dumps(info.to_dict(), indent=2)
