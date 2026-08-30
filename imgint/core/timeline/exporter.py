"""Exporters for forensic timeline reports (Terminal, JSON, Plaso/Timesketch CSV)."""

from __future__ import annotations
import csv
import io
import json
from pathlib import Path
from typing import Dict, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from imgint.core.timeline.reconstructor import TimelineReport


class TimelineExporter:
    """Exports TimelineReport to Rich terminal tables, JSON, or Plaso/Timesketch CSV."""

    @classmethod
    def render_terminal(cls, report: TimelineReport, console: Console) -> None:
        # Header Panel
        panel_content = Text()
        panel_content.append(f"Total Timeline Events: ", style="dim")
        panel_content.append(f"{report.total_events}\n", style="bold cyan")
        if report.timespan_start and report.timespan_end:
            panel_content.append(f"Timeline Span:         ", style="dim")
            panel_content.append(f"{report.timespan_start}  -->  {report.timespan_end}\n", style="yellow")
        if report.total_duration_str:
            panel_content.append(f"Elapsed Duration:      ", style="dim")
            panel_content.append(f"{report.total_duration_str}\n", style="green")

        if report.detected_anomalies:
            panel_content.append(f"\n[!] Chronological Anomalies ({len(report.detected_anomalies)}):\n", style="bold red")
            for a in report.detected_anomalies:
                panel_content.append(f" • {a}\n", style="red")

        console.print(Panel(panel_content, title="[bold]matazero Forensic Timeline & Chronolocation Reconstruction[/bold]", border_style="cyan"))

        # Events Table
        table = Table(title=f"Chronological Evidence Sequence ({report.total_events} Events)", show_header=True)
        table.add_column("#", justify="right", style="dim")
        table.add_column("Timestamp (UTC/Offset)", style="bold green")
        table.add_column("File Name", style="cyan")
        table.add_column("Delta (Previous)", justify="right", style="yellow")
        table.add_column("Source Tag", style="dim")
        table.add_column("Camera Model", style="white")
        table.add_column("Clock Drift (vs GPS)", justify="right", style="magenta")

        for idx, ev in enumerate(report.events, start=1):
            delta_str = "-"
            if ev.time_delta_from_previous_sec is not None:
                d_sec = ev.time_delta_from_previous_sec
                if d_sec < 60:
                    delta_str = f"+{d_sec:.1f}s"
                elif d_sec < 3600:
                    delta_str = f"+{d_sec/60:.1f}m"
                else:
                    delta_str = f"+{d_sec/3600:.1f}h"

            drift_str = "-"
            if ev.camera_clock_drift_seconds is not None:
                drift_s = ev.camera_clock_drift_seconds
                drift_str = f"{drift_s:+.1f}s"
                if abs(drift_s) > 60:
                    drift_str = f"[bold red]{drift_str}[/bold red]"

            cam_str = f"{ev.camera_make or ''} {ev.camera_model or ''}".strip() or "-"
            ts_str = ev.primary_timestamp.strftime("%Y-%m-%d %H:%M:%S")

            table.add_row(
                str(idx),
                ts_str,
                ev.file_name,
                delta_str,
                ev.timestamp_source,
                cam_str,
                drift_str,
            )

        console.print(table)

    @classmethod
    def to_json(cls, report: TimelineReport) -> str:
        return json.dumps(report.to_dict(), indent=2)

    @classmethod
    def to_plaso_csv(cls, report: TimelineReport) -> str:
        """Exports timeline in Plaso / Timesketch 7-column CSV format."""
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["datetime", "timestamp_desc", "source", "source_long", "message", "parser", "display_name", "tag"])

        for ev in report.events:
            dt_str = ev.primary_timestamp.strftime("%Y-%m-%dT%H:%M:%S+00:00")
            msg = f"Evidence Image: {ev.file_name} (SHA-256: {ev.sha256[:16]}...) | Camera: {ev.camera_make or ''} {ev.camera_model or ''}".strip()
            if ev.camera_clock_drift_seconds is not None:
                msg += f" | Clock Drift: {ev.camera_clock_drift_seconds:+.1f}s"
            tag = "anomaly" if ev.anomalies else "evidence_capture"

            writer.writerow([
                dt_str,
                ev.timestamp_source,
                "IMAGE",
                "Digital Image Forensics (matazero)",
                msg,
                "matazero_timeline",
                ev.file_name,
                tag,
            ])

        return out.getvalue()
