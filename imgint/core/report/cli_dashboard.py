"""Visual Executive CLI Dashboard & Deep Forensic Tree Renderer.

Provides an ultra-clean, simple-to-read executive summary dashboard by default,
and a rich hierarchical forensic tree breakdown with --deep / --details.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.columns import Columns

from imgint.core.model.record import AnalysisRecord
from imgint.core.model.finding import Finding, Confidence
from imgint.core.geo.locator import GeoLocator


class CliDashboard:
    """Renders clean, beautiful, and intuitive CLI dashboards for forensic analysis."""

    @classmethod
    def render_summary_dashboard(cls, record: AnalysisRecord, console: Console) -> None:
        """Renders an intuitive, high-readability executive summary dashboard in the terminal."""
        # 1. Header Banner
        header_text = Text()
        header_text.append(" TARGET EVIDENCE: ", style="bold white on blue")
        header_text.append(f" {record.file_path} ", style="bold white")
        header_text.append(f"({record.file_size:,} bytes | {record.mime_type})\n", style="cyan")
        header_text.append(f"SHA-256: {record.sha256}", style="dim")
        if record.data_stream_sha256:
            header_text.append(f"\nPixel Data SHA: {record.data_stream_sha256}", style="dim")

        console.print(Panel(header_text, title="[bold]matazero Evidence Overview[/bold]", border_style="blue"))

        # 2. Authenticity & Integrity Verdict Card
        verdict = record.authenticity_verdict or {}
        is_auth = verdict.get("is_authentic")
        conf_pct = int(verdict.get("confidence_score", 0.5) * 100)
        risk = str(verdict.get("risk_level", "UNKNOWN")).upper()
        label = verdict.get("verdict_label", "Inconclusive")

        if is_auth is True:
            v_style = "bold white on dark_green"
            v_border = "green"
            v_icon = "✔"
            status_text = f"{v_icon} AUTHENTIC ORIGINAL"
        elif is_auth is False:
            v_style = "bold white on red"
            v_border = "red"
            v_icon = "✖"
            status_text = f"{v_icon} MANIPULATION / PAYLOAD DETECTED"
        else:
            v_style = "bold black on yellow"
            v_border = "yellow"
            v_icon = "ℹ"
            status_text = f"{v_icon} {label.upper()}"

        verdict_content = Text()
        verdict_content.append(f"  {status_text}  ", style=v_style)
        verdict_content.append(f"   Confidence: {conf_pct}%   |   Risk Level: {risk}\n\n", style="bold")

        reasons = verdict.get("supporting_reasons", [])
        if reasons:
            for r in reasons:
                verdict_content.append(f" • {r}\n", style="white")
        else:
            verdict_content.append(" • Analysis completed based on available metadata and structural markers.\n", style="dim")

        console.print(Panel(verdict_content, title="[bold]Integrity & Authenticity Verdict[/bold]", border_style=v_border))

        # 3. Two-Column Information Cards: Device Fingerprint & Geolocation
        left_table = Table(show_header=False, box=None, padding=(0, 1))
        left_table.add_column("Key", style="bold cyan", width=18)
        left_table.add_column("Value", style="white")

        # Camera & Device Fields
        make = next((f.value for f in record.fields if f.name.lower() in ("make", "camera_make")), None)
        model = next((f.value for f in record.fields if f.name.lower() in ("model", "camera_model")), None)
        software = next((f.value for f in record.fields if f.name.lower() in ("software", "processing_software")), None)
        lens = next((f.value for f in record.fields if "lens" in f.name.lower()), None)
        date_orig = next((f.value for f in record.fields if f.name.lower() in ("datetimeoriginal", "createdate", "created")), None)
        dim_f = next((f.value for f in record.findings if f.name == "image_dimensions"), None)

        left_table.add_row("Device Make:", str(make) if make else "[dim]Not specified[/dim]")
        left_table.add_row("Device Model:", str(model) if model else "[dim]Not specified[/dim]")
        if lens:
            left_table.add_row("Lens Model:", str(lens))
        left_table.add_row("Software/Editor:", str(software) if software else "[dim]None recorded (Direct Capture)[/dim]")
        left_table.add_row("Capture Date:", str(date_orig) if date_orig else "[dim]No timestamp[/dim]")
        if dim_f and isinstance(dim_f, dict):
            left_table.add_row("Dimensions:", f"{dim_f.get('width')} x {dim_f.get('height')} px ({dim_f.get('mode', '')})")

        # Encoder Fingerprint
        enc_f = next((f.value for f in record.findings if f.name == "encoder_composite_fingerprint"), None)
        if enc_f and isinstance(enc_f, dict):
            qs = enc_f.get("estimated_qualities", [])
            q_str = f"Q~{qs[0]}" if qs else "Standard"
            ss = enc_f.get("subsampling", "Unknown")
            left_table.add_row("Compression:", f"{q_str} (Chroma: {ss})")

        device_panel = Panel(left_table, title="[bold]Hardware & Device Profile[/bold]", border_style="bright_blue")

        # Geolocation Card
        right_table = Table(show_header=False, box=None, padding=(0, 1))
        right_table.add_column("Key", style="bold green", width=18)
        right_table.add_column("Value", style="white")

        gps_f = next((f.value for f in record.findings if f.name in ("gps_coordinates_claimed", "gps_location_fix")), None)
        solar_f = next((f.value for f in record.findings if f.name == "solar_chronolocation_claimed"), None)

        if gps_f and isinstance(gps_f, dict) and gps_f.get("latitude") is not None:
            lat = float(gps_f.get("latitude"))
            lon = float(gps_f.get("longitude"))
            place = gps_f.get("nearest_place") or gps_f.get("closest_city")
            country = gps_f.get("country") or gps_f.get("country_code")
            tz = gps_f.get("timezone")
            alt = gps_f.get("altitude_m") or gps_f.get("altitude_meters")

            if abs(lat) < 0.0001 and abs(lon) < 0.0001:
                right_table.add_row("GPS Coordinates:", "[yellow]0.000000, 0.000000 (Uninitialized Lock / Null Island)[/yellow]")
                right_table.add_row("Location:", "[dim]Geocoding suppressed (No satellite lock)[/dim]")
            else:
                lat_lon_str = f"{lat:.6f}, {lon:.6f}"
                dms_str = GeoLocator.format_dms(lat, lon)
                gmaps_url = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
                osm_url = f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}"

                right_table.add_row("GPS (Lat, Lon):", f"[bold white]{lat_lon_str}[/bold white]")
                right_table.add_row("DMS Format:", f"[dim]{dms_str}[/dim]")
                if place:
                    right_table.add_row("Nearest City:", f"{place}, {country}" if country else str(place))
                if tz:
                    right_table.add_row("Timezone:", str(tz))
                if alt is not None:
                    right_table.add_row("Altitude:", f"{alt} meters")
                if solar_f and isinstance(solar_f, dict):
                    phase = solar_f.get("day_phase", "Daylight")
                    el = solar_f.get("solar_elevation_degrees", 0.0)
                    az = solar_f.get("solar_azimuth_degrees", 0.0)
                    right_table.add_row("Solar Chrono:", f"{phase} (Elevation: {el}°, Azimuth: {az}°)")

                right_table.add_row("Google Maps:", f"[cyan underline link={gmaps_url}]{gmaps_url}[/cyan underline link]")
                right_table.add_row("OpenStreetMap:", f"[link={osm_url}]{osm_url}[/link]")
        else:
            right_table.add_row("GPS Coordinates:", "[dim]No geolocation metadata found in container[/dim]")
            right_table.add_row("Chronolocation:", "[dim]No solar angle data available[/dim]")

        geo_panel = Panel(right_table, title="[bold]Geospatial & Chronolocation[/bold]", border_style="bright_green")

        console.print(Columns([device_panel, geo_panel], equal=True))

        # 4. Hidden Data, Embedded Media & Threat Alerts
        threats_table = Table(show_header=True, header_style="bold magenta", expand=True)
        threats_table.add_column("Category", width=22)
        threats_table.add_column("Status / Findings", style="white")

        # Check Carved Payloads
        trailing_units = [u for u in record.structural_units if "TRAILING" in u.name or "CARVED" in u.name]
        if trailing_units:
            t_msg = f"[bold red]✖ FOUND {len(trailing_units)} TRAILING DATA STREAM(S)[/bold red]: " + ", ".join(
                f"{u.description} ({u.length:,} B @ 0x{u.offset:X})" for u in trailing_units
            )
            threats_table.add_row("[bold red]Trailing Payload[/bold red]", t_msg)
        else:
            threats_table.add_row("Trailing Data", "[green]✔ Clean (No unparsed trailing bytes after EOF)[/green]")

        # Check Embedded Images / Media (PPTX / DOCX / Previews / Thumbnails)
        media_units = [u for u in record.structural_units if "EMBEDDED_IMAGE" in u.name or "PREVIEW" in u.name or "THUMBNAIL" in u.name]
        if media_units:
            m_msg = f"[bold cyan]Found {len(media_units)} embedded asset(s)[/bold cyan]: " + ", ".join(
                f"{u.name.replace('EMBEDDED_IMAGE:', '')} ({u.length:,} B)" for u in media_units[:5]
            )
            if len(media_units) > 5:
                m_msg += f" ... (+{len(media_units) - 5} more)"
            threats_table.add_row("Embedded Media", m_msg)
        else:
            threats_table.add_row("Embedded Media", "[dim]No secondary embedded thumbnails or slide images[/dim]")

        # Check LSB Stego Anomalies
        lsb_f = next((f.value for f in record.findings if f.name == "lsb_entropy_screening"), None)
        if lsb_f and isinstance(lsb_f, dict) and lsb_f.get("lsb_anomaly"):
            threats_table.add_row("[bold yellow]LSB Stego Anomaly[/bold yellow]", f"[bold yellow]▲ High bit density ({lsb_f.get('lsb_bit_density')}) flagged[/bold yellow]")
        else:
            threats_table.add_row("LSB Stego Check", "[green]✔ Normal bit density (Natural sensor noise)[/green]")

        console.print(Panel(threats_table, title="[bold]Hidden Data, Embedded Media & Threat Screening[/bold]", border_style="magenta"))

        # 5. Top Extracted Metadata Table
        if record.fields:
            meta_table = Table(title=f"Extracted Metadata Sample ({len(record.fields)} Total Fields)", expand=True)
            meta_table.add_column("Field Name", style="bold cyan", width=25)
            meta_table.add_column("Standard", style="yellow", width=10)
            meta_table.add_column("Tag Offset", style="dim", width=12)
            meta_table.add_column("Value Location", style="dim", width=15)
            meta_table.add_column("Value Preview", style="white")

            for fld in record.fields[:12]:
                tag_off = f"0x{fld.offset:X}" if fld.offset is not None else "-"
                val_loc = f"0x{fld.value_offset:X}" if fld.value_offset is not None else "-"
                meta_table.add_row(fld.name, fld.standard, tag_off, val_loc, str(fld.value)[:55])

            console.print(meta_table)
            if len(record.fields) > 12:
                console.print(f"[dim] Use [bold]--deep[/bold] or [bold]-f report[/bold] to inspect all {len(record.fields)} fields with exact byte offsets.[/dim]\n")

    @classmethod
    def render_deep_tree(cls, record: AnalysisRecord, console: Console) -> None:
        """Renders an exhaustive hierarchical forensic tree breakdown."""
        tree = Tree(f"[bold white on blue] matazero DEEP FORENSIC TREE [/bold white on blue] — [bold]{record.file_path}[/bold] ({record.file_size:,} B)")

        # 1. Container Structure
        c_tree = tree.add("[bold cyan]1. Container Structure & Units[/bold cyan]")
        for u in record.structural_units:
            c_tree.add(f"[bold]{u.name}[/bold] (Offset: 0x{u.offset:X}, Length: {u.length:,} B) — {u.description}")

        # 2. Metadata Blocks
        b_tree = tree.add(f"[bold yellow]2. Metadata Blocks ({len(record.metadata_blocks)} blocks)[/bold yellow]")
        for b in record.metadata_blocks:
            b_tree.add(f"[bold]{b.kind}[/bold] @ 0x{b.offset:X} ({b.length:,} B) — Source: {b.source_unit}")

        # 3. Extracted Metadata Fields
        f_tree = tree.add(f"[bold green]3. Complete Metadata Field Inventory ({len(record.fields)} fields)[/bold green]")
        for fld in record.fields:
            off_str = f"Tag @ 0x{fld.offset:X}" if fld.offset is not None else ""
            val_off_str = f"Val @ 0x{fld.value_offset:X}" if fld.value_offset is not None else ""
            locs = ", ".join(filter(None, [off_str, val_off_str]))
            loc_disp = f" ({locs})" if locs else ""
            f_tree.add(f"[bold]{fld.name}[/bold] [{fld.standard}]{loc_disp} = [cyan]{fld.value}[/cyan]")

        # 4. Forensic Findings by Tier
        findings_tree = tree.add("[bold magenta]4. Forensic Findings (Tiers 1–7)[/bold magenta]")
        for t in range(1, 8):
            tier_findings = [f for f in record.findings if f.tier == t]
            if tier_findings:
                t_branch = findings_tree.add(f"[bold]Tier {t} Findings ({len(tier_findings)})[/bold]")
                for f in tier_findings:
                    t_branch.add(f"[bold]{f.name}[/bold] [{f.confidence.value}] — Extractor: {f.extractor}\nValue: {f.value}")

        # 5. Hashes & Integrity
        h_tree = tree.add("[bold white]5. Cryptographic Hashes & Integrity[/bold white]")
        h_tree.add(f"File SHA-256: {record.sha256}")
        if record.data_stream_sha256:
            h_tree.add(f"Data Stream SHA-256: {record.data_stream_sha256}")

        console.print(tree)
        console.print("")
