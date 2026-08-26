"""Command-line interface for imgint per SRD §3.10 and SRS §3.1."""

from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from imgint import __version__
from imgint.core.evidence.store import EvidenceStore, EvidenceCustodyError
from imgint.core.governance.audit import AuditLogger, verify_audit_chain
from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError
from imgint.core.pipeline import AnalysisPipeline
from imgint.core.report.renderer import ReportRenderer
from imgint.core.report.manifest import HashManifestGenerator
from imgint.core.clean.cleaner import MetadataCleaner
from imgint.core.source.reader import BoundedReader
from imgint.core.sniff.detector import FormatDetector
from imgint.core.container import create_default_container_registry
from imgint.core.artefact.carver import PayloadCarver
from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.fingerprint.dqt import DqtExtractor
from imgint.core.fingerprint.subsampling import SubsamplingExtractor
from imgint.core.fingerprint.order import SegmentOrderExtractor

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


@click.group()
@click.version_option(version=__version__, prog_name="matazero")
def cli() -> None:
    """matazero — Image Intelligence Toolkit for Ethical OSINT and Digital Forensics."""
    pass


# -----------------------------------------------------------------------------
# Subcommand: scope
# -----------------------------------------------------------------------------
@cli.group()
def scope() -> None:
    """Create, validate, or display an authorization scope."""
    pass


@scope.command("create")
@click.option("-c", "--case", "case_id", required=True, help="Case identifier (e.g. CASE-2026-001)")
@click.option("-p", "--purpose", required=True, help="Investigation purpose")
@click.option("-l", "--legal-basis", required=True, help="Lawful basis (e.g. Subpoena, Consent, Legitimate Interest)")
@click.option("-a", "--authorising-party", required=True, help="Authorising authority / lead investigator")
@click.option("-d", "--days", default=30, type=int, help="Validity period in days (default: 30)")
@click.option("-o", "--out", "out_path", required=True, type=click.Path(), help="Output path for scope JSON file")
@click.option("-k", "--secret", default=None, help="Optional HMAC secret key for cryptographic signing")
def scope_create(case_id: str, purpose: str, legal_basis: str, authorising_party: str, days: int, out_path: str, secret: Optional[str]) -> None:
    """Create a new signed authorization scope file."""
    exp_date = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    auth_scope = AuthorizationScope(
        case_id=case_id,
        purpose=purpose,
        legal_basis=legal_basis,
        authorising_party=authorising_party,
        data_subject_categories=["Image Source Files"],
        permitted_operations=["tier1", "tier2", "tier3", "tier4", "tier5", "tier6", "tier7"],
        retention_period_days=days,
        expiry_date=exp_date,
    )
    auth_scope.save_to_file(out_path, secret_key=secret)
    console.print(f"[green][OK][/green] Authorization scope created at [bold]{out_path}[/bold]")
    console.print(f"  Case ID:     {case_id}")
    console.print(f"  Expiry:      {exp_date}")
    console.print(f"  Scope Hash:  {auth_scope.scope_hash}")
    if secret:
        console.print(f"  Signature:   {auth_scope.signature}")


@scope.command("validate")
@click.argument("scope_file", type=click.Path(exists=True))
@click.option("-k", "--secret", default=None, help="Optional HMAC secret key for signature verification")
def scope_validate(scope_file: str, secret: Optional[str]) -> None:
    """Validate the integrity and expiration status of a scope file."""
    try:
        s = AuthorizationScope.load_from_file(scope_file, secret_key=secret)
        console.print(f"[green][OK] Scope is VALID[/green]")
        console.print(f"  Case ID:     {s.case_id}")
        console.print(f"  Purpose:     {s.purpose}")
        console.print(f"  Legal Basis: {s.legal_basis}")
        console.print(f"  Expires:     {s.expiry_date}")
        console.print(f"  Scope Hash:  {s.scope_hash}")
    except ScopeValidationError as e:
        err_console.print(f"[red][X] Scope INVALID: {e}[/red]")
        sys.exit(6)


# -----------------------------------------------------------------------------
# Subcommand: analyze
# -----------------------------------------------------------------------------
@cli.command("analyze")
@click.argument("targets", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("-s", "--scope", "scope_path", default=lambda: os.environ.get("IMGINT_SCOPE"), help="Path to authorization scope JSON")
@click.option("-a", "--self-audit", is_flag=True, help="Operate in self-audit mode on personal files without a scope")
@click.option("-t", "--tiers", default="1,2,3,4,5,6,7", help="Comma-separated tier list (e.g. 1,2,3)")
@click.option("-f", "--format", "out_fmt", type=click.Choice(["report", "json", "ndjson", "table", "html"]), default="report", help="Output format")
@click.option("--store", "store_path", default="./evidence_store", help="Evidence store directory")
@click.option("--audit-log", "audit_path", default="./audit.jsonl", help="Audit log file path")
@click.option("-n", "--allow-network", is_flag=True, help="Enable disclosed external lookups (GR-4.1)")
@click.option("-e", "--ela", is_flag=True, help="Enable Error Level Analysis in Tier 6")
@click.option("-c", "--carve", is_flag=True, help="Automatically carve trailing archives or payloads")
@click.option("--carve-dir", default="./evidence_store/carved", help="Directory to save carved payloads")
@click.option("-o", "--out", "out_file", default=None, type=click.Path(), help="Write output to file instead of stdout")
def analyze(
    targets: List[str],
    scope_path: Optional[str],
    self_audit: bool,
    tiers: str,
    out_fmt: str,
    store_path: str,
    audit_path: str,
    allow_network: bool,
    ela: bool,
    carve: bool,
    carve_dir: str,
    out_file: Optional[str],
) -> None:
    """Run 7 extraction tiers over evidence files."""
    # Scope resolution
    auth_scope: Optional[AuthorizationScope] = None
    if self_audit:
        auth_scope = AuthorizationScope.create_self_audit_scope()
    elif scope_path:
        try:
            auth_scope = AuthorizationScope.load_from_file(scope_path)
        except ScopeValidationError as e:
            err_console.print(f"[red]Authorization failure (Exit 6): {e}[/red]")
            sys.exit(6)
    else:
        err_console.print(
            "[red]Authorization failure (Exit 6): No authorization scope provided.\n"
            "Provide --scope PATH, set IMGINT_SCOPE, or use --self-audit for personal files.[/red]"
        )
        sys.exit(6)

    # Initialize store and audit log
    evidence_store = EvidenceStore(store_path) if not self_audit else None
    audit_logger = AuditLogger(audit_path, scope_id=auth_scope.case_id) if not self_audit else None

    # Parse tiers
    try:
        tier_set = {int(t.strip()) for t in tiers.split(",") if t.strip()}
    except ValueError:
        err_console.print("[red]Invalid --tiers value. Expected numbers separated by comma (e.g. 1,2,3)[/red]")
        sys.exit(2)

    pipeline = AnalysisPipeline(
        scope=auth_scope,
        audit_logger=audit_logger,
        evidence_store=evidence_store,
        allow_network=allow_network,
        enable_ela=ela,
        selected_tiers=tier_set,
    )

    records = []
    has_error = False

    for target in targets:
        try:
            rec = pipeline.analyze_file(target)
            records.append(rec)
            if any(d.level == "error" for d in rec.diagnostics):
                has_error = True

            # Automatic Payload Carving if requested
            if carve and rec.structural_units:
                reader = BoundedReader(Path(target))
                carved = PayloadCarver.carve_trailing_payload(reader, rec.structural_units, carve_dir)
                if carved:
                    console.print(
                        f"[green][OK] Carved {carved.payload_type} ({carved.size:,} B) from {target} -> [bold]{carved.output_path}[/bold][/green]"
                    )
        except EvidenceCustodyError as e:
            err_console.print(f"[bold red]CRITICAL CUSTODY FAILURE (Exit 7): {e}[/bold red]")
            sys.exit(7)
        except Exception as e:
            err_console.print(f"[red]Analysis error for {target}: {e}[/red]")
            has_error = True

    # Render output
    if out_fmt == "json":
        rendered = ReportRenderer.render_json(records)
    elif out_fmt == "ndjson":
        rendered = ReportRenderer.render_ndjson(records)
    elif out_fmt == "html":
        rendered = ReportRenderer.render_html(records)
    elif out_fmt == "table":
        # Render a summary table
        table = Table(title="matazero Analysis Summary")
        table.add_column("File Path", style="cyan")
        table.add_column("Format", style="green")
        table.add_column("Findings", justify="right")
        table.add_column("SHA-256", style="dim")
        for r in records:
            table.add_row(r.file_path, r.mime_type, str(len(r.findings)), r.sha256[:16] + "...")
        console.print(table)
        rendered = ""
    else:  # report
        rendered = "\n\n".join(ReportRenderer.render_report(r) for r in records)

    if rendered:
        if out_file:
            Path(out_file).write_text(rendered, encoding="utf-8")
            console.print(f"[green][OK] Report written to {out_file}[/green]")
        else:
            print(rendered)

    if has_error:
        sys.exit(4)  # Partial success


# -----------------------------------------------------------------------------
# Subcommand: probe
# -----------------------------------------------------------------------------
@cli.command("probe")
@click.argument("target", type=click.Path(exists=True))
def probe(target: str) -> None:
    """Dump container segment and chunk structure with byte offsets."""
    p = Path(target)
    reader = BoundedReader(p)
    detected = FormatDetector.detect(reader)

    console.print(f"[bold cyan]matazero Container Probe[/bold cyan] — {p.name} ({detected.format_name})")
    console.print(f"MIME: {detected.mime_type} | Size: {reader.size:,} bytes | Magic: {detected.magic_hex}\n")

    registry = create_default_container_registry()
    container_reader = registry.get_reader(detected.format_name)
    if not container_reader:
        err_console.print(f"[red]Unsupported container format: {detected.format_name}[/red]")
        sys.exit(3)

    units, blocks, diags = container_reader.read(reader)

    table = Table(title=f"Structural Units ({len(units)})")
    table.add_column("Offset", style="dim", justify="right")
    table.add_column("Unit Name", style="bold green")
    table.add_column("Length", justify="right")
    table.add_column("Description", style="cyan")

    for u in units:
        table.add_row(f"0x{u.offset:06X}", u.name, f"{u.length:,} B", u.description or "")

    console.print(table)

    if blocks:
        block_table = Table(title=f"Metadata Blocks ({len(blocks)})")
        block_table.add_column("Kind", style="bold yellow")
        block_table.add_column("Offset", style="dim", justify="right")
        block_table.add_column("Length", justify="right")
        block_table.add_column("Source Unit", style="cyan")
        for b in blocks:
            block_table.add_row(b.kind, f"0x{b.offset:06X}", f"{b.length:,} B", b.source_unit or "")
        console.print(block_table)


# -----------------------------------------------------------------------------
# Subcommand: audit
# -----------------------------------------------------------------------------
@cli.group()
def audit() -> None:
    """Verify or export the tamper-evident audit log."""
    pass


@audit.command("verify")
@click.argument("audit_file", default="./audit.jsonl", type=click.Path(exists=True))
def audit_verify(audit_file: str) -> None:
    """Cryptographically verify the hash chain of an audit log (GR-2.7)."""
    is_valid, broken_idx, message = verify_audit_chain(audit_file)
    if is_valid:
        console.print(f"[green][OK] {message}[/green]")
    else:
        err_console.print(f"[bold red][X] AUDIT CHAIN COMPROMISED (Exit 7): {message}[/bold red]")
        sys.exit(7)


# -----------------------------------------------------------------------------
# Subcommand: clean
# -----------------------------------------------------------------------------
@cli.command("clean")
@click.argument("target", type=click.Path(exists=True))
@click.option("-o", "--out", "out_path", default=None, type=click.Path(), help="Output path for cleaned file")
@click.option("-c", "--commit", is_flag=True, help="Required to execute modification (dry-run without it per FR-10.9)")
def clean(target: str, out_path: Optional[str], commit: bool) -> None:
    """Losslessly remove metadata in self-audit mode."""
    if not commit:
        console.print("[yellow][DRY RUN] Metadata cleaning simulated. Use --commit to write cleaned output.[/yellow]")
        cleaned, orig_s, clean_s = MetadataCleaner.clean_file(target)
        console.print(f"Original size: {orig_s:,} bytes -> Cleaned size: {clean_s:,} bytes (Saved {orig_s - clean_s:,} bytes)")
        return

    dest = out_path or target
    cleaned, orig_s, clean_s = MetadataCleaner.clean_file(target, output_path=dest)
    console.print(f"[green][OK] Cleaned metadata written to {dest}[/green]")
    console.print(f"  Original size: {orig_s:,} bytes")
    console.print(f"  Cleaned size:  {clean_s:,} bytes (Reduced by {orig_s - clean_s:,} bytes)")


# -----------------------------------------------------------------------------
# Subcommand: corpus
# -----------------------------------------------------------------------------
@cli.group()
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


# -----------------------------------------------------------------------------
# Subcommand: completion
# -----------------------------------------------------------------------------
@cli.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str) -> None:
    """Generate shell completion scripts (bash, zsh, fish)."""
    if shell == "bash":
        console.print('# bash completion for matazero\neval "$(_MATAZERO_COMPLETE=bash_source matazero)"')
    elif shell == "zsh":
        console.print('# zsh completion for matazero\neval "$(_MATAZERO_COMPLETE=zsh_source matazero)"')
    elif shell == "fish":
        console.print('# fish completion for matazero\neval (env _MATAZERO_COMPLETE=fish_source matazero)')


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
