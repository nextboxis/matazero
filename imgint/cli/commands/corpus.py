from __future__ import annotations
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.source.reader import BoundedReader
from imgint.core.sniff.detector import FormatDetector
from imgint.core.container import create_default_container_registry
from imgint.core.fingerprint import (
    DqtExtractor,
    SubsamplingExtractor,
    SegmentOrderExtractor,
)

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

@click.group()
def corpus() -> None:
    """Manage and inspect the reference encoder fingerprint corpus."""
    pass


@corpus.command("list")
def corpus_list() -> None:
    """List all registered device and platform encoder profiles."""
    ref_corpus = ReferenceCorpus()
    table = Table(title=f"Reference Encoder Corpus ({len(ref_corpus.entries)} Profiles — v{ref_corpus.version})")
    table.add_column("ID", style="bold cyan")
    table.add_column("Device / Platform Model", style="green")
    table.add_column("Encoder Software", style="yellow")
    table.add_column("Chroma", style="dim")
    table.add_column("Confidence", style="magenta")

    for e in ref_corpus.entries:
        table.add_row(
            e.entry_id,
            e.device_model,
            e.encoder_software,
            e.subsampling,
            f"[{e.confidence.upper()}]",
        )

    console.print(table)


@corpus.command("learn")
@click.argument("target", type=click.Path(exists=True))
@click.option("-i", "--id", "entry_id", required=True, help="Unique profile identifier (e.g. my_custom_device)")
@click.option("-m", "--model", required=True, help="Device or camera model description")
@click.option("-e", "--encoder", default="Custom JPEG Pipeline", help="Encoder software description")
def corpus_learn(target: str, entry_id: str, model: str, encoder: str) -> None:
    """Learn and register a new camera fingerprint from a reference JPEG."""
    p = Path(target)
    reader = BoundedReader(p)
    detected = FormatDetector.detect(reader)
    if detected.format_name != "JPEG":
        err_console.print(f"[red]Corpus learning currently requires JPEG reference images (detected: {detected.format_name})[/red]")
        sys.exit(3)

    registry = create_default_container_registry()
    container_reader = registry.get_reader("JPEG")
    units, blocks, diags = container_reader.read(reader)

    dqt_tables = []
    subsampling_info = None
    for u in units:
        if u.name == "DQT" and u.payload:
            dqt_tables.extend(DqtExtractor.extract_from_dqt_payload(u.payload))
        elif u.name.startswith("SOF") and u.payload:
            subsampling_info = SubsamplingExtractor.extract_from_sof_payload(u.payload)

    if not dqt_tables:
        err_console.print("[red]No DQT Quantization Tables found in reference image[/red]")
        sys.exit(1)

    lum_sample = dqt_tables[0].values
    seq = SegmentOrderExtractor.extract_sequence(units)
    ss_str = subsampling_info.notation if subsampling_info else "4:2:0"

    entry = CorpusEntry(
        entry_id=entry_id,
        device_model=model,
        encoder_software=encoder,
        processing_chain="Learned reference profile (User Corpus)",
        subsampling=ss_str,
        dqt_luminance_sample=lum_sample,
        segment_prefix=seq[:6],
        confidence="indicative",
    )

    ref_corpus = ReferenceCorpus()
    ref_corpus.add_user_entry(entry)

    console.print(f"[green][OK] Fingerprint profile [bold]{entry_id}[/bold] learned and saved to user corpus![/green]")
    console.print(f"  Model:       {model}")
    console.print(f"  Encoder:     {encoder}")
    console.print(f"  Subsampling: {ss_str}")
    console.print(f"  DQT Samples: {len(lum_sample)} values")
