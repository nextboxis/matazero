"""Forensic analysis orchestrator and pipeline execution per ARCHITECTURE §3."""

from __future__ import annotations
import hashlib
from pathlib import Path
from typing import List, Optional, Set, Tuple
from imgint import __version__
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import AnalysisRecord, Diagnostic, Field, MetadataBlock, StructuralUnit
from imgint.core.source.reader import BoundedReader
from imgint.core.sniff.detector import FormatDetector
from imgint.core.container import create_default_container_registry
from imgint.core.standard import create_default_standard_registry
from imgint.core.fingerprint import (
    DqtExtractor,
    DhtExtractor,
    SubsamplingExtractor,
    SegmentOrderExtractor,
    CompositeFingerprintBuilder,
    ReferenceCorpus,
    FingerprintMatcher,
)
from imgint.core.artefact import (
    ThumbnailExtractor,
    MpfExtractor,
    TrailingDataExtractor,
    PreviewExtractor,
    ContainerAnomalyDetector,
)
from imgint.core.analyzer import create_default_analyzer_registry, AnalysisContext
from imgint.core.analyzer.verdict import AuthenticityEvaluator
from imgint.core.governance.scope import AuthorizationScope, ScopeValidationError
from imgint.core.governance.audit import AuditLogger
from imgint.core.evidence.store import EvidenceStore, EvidenceCustodyError
from imgint.core.event import (
    ForensicEventBus,
    AnalysisStartedEvent,
    AnalysisCompletedEvent,
    AnomalyDetectedEvent,
    VerdictEvaluatedEvent,
)
from imgint.core.skill import SkillRegistry


class AnalysisPipeline:
    """Coordinates multi-tier forensic extraction and governance enforcement."""

    def __init__(
        self,
        scope: Optional[AuthorizationScope] = None,
        audit_logger: Optional[AuditLogger] = None,
        evidence_store: Optional[EvidenceStore] = None,
        corpus: Optional[ReferenceCorpus] = None,
        allow_network: bool = False,
        enable_ela: bool = False,
        selected_tiers: Optional[Set[int]] = None,
    ):
        self.scope = scope
        self.audit_logger = audit_logger
        self.evidence_store = evidence_store
        self.corpus = corpus or ReferenceCorpus()
        self.allow_network = allow_network
        self.enable_ela = enable_ela
        self.selected_tiers = selected_tiers or {1, 2, 3, 4, 5, 6, 7}

        self.container_registry = create_default_container_registry()
        self.standard_registry = create_default_standard_registry()
        self.analyzer_registry = create_default_analyzer_registry()

    def analyze_file(self, file_path: str | Path) -> AnalysisRecord:
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Enforce GR-1.1: Scope check
        if self.scope is None:
            raise ScopeValidationError(
                "No authorization scope loaded. Operation refused per SRD GR-1.1. "
                "Provide --scope PATH or run with --self-audit for personal files."
            )
        if self.scope.is_expired:
            raise ScopeValidationError(
                f"Authorization scope expired on {self.scope.expiry_date}. "
                "Operation refused per SRD GR-1.3."
            )

        # Ingest into evidence store if active
        file_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        working_path = path

        if self.evidence_store:
            ingested = self.evidence_store.ingest(path)
            file_sha256 = ingested.sha256
            working_path = Path(ingested.working_copy_path)

        if self.audit_logger:
            self.audit_logger.log(
                action="file_analysis_started",
                outcome="SUCCESS",
                target_hash=file_sha256,
                details={"file_path": str(path), "selected_tiers": list(self.selected_tiers)},
            )

        # Publish AnalysisStartedEvent to ForensicEventBus
        ForensicEventBus.get_default().publish(AnalysisStartedEvent(file_path=str(path)))

        # Create record
        record = AnalysisRecord(
            file_path=str(path),
            file_size=path.stat().st_size,
            mime_type="application/octet-stream",
            sha256=file_sha256,
            tool_version=__version__,
            corpus_version=self.corpus.version,
            scope_id=self.scope.case_id if self.scope else "UNSCOPED",
            not_established=[
                "Authenticity or manipulation verdicts (prohibited per GR-3.6)",
                "Original capture context when metadata is absent (normal platform distribution per FR-7.9)",
                "Operator identity or biometric confirmation (refused per GR-3.1)",
            ],
        )

        reader = BoundedReader(working_path)

        # Format detection (FR-1.1, FR-1.2)
        detected = FormatDetector.detect(reader)
        record.mime_type = detected.mime_type

        if not detected.is_supported:
            record.add_diagnostic(
                level="error",
                message=f"Unsupported format: magic bytes {detected.magic_hex}",
                source="format_detector",
                offset=0,
            )
            return record

        mismatch_finding = FormatDetector.check_extension_mismatch(detected, path)
        if mismatch_finding:
            record.add_finding(mismatch_finding)

        # Tier 1 & 2 Container Walk
        container_reader = self.container_registry.get_reader(detected.format_name)
        if not container_reader:
            record.add_diagnostic(
                level="error",
                message=f"No container reader for format {detected.format_name}",
                source="container_registry",
            )
            return record

        units, blocks, container_diags = container_reader.read(reader)
        record.structural_units = units
        record.metadata_blocks = blocks
        record.diagnostics.extend(container_diags)

        # Standard Metadata Parsing (Tier 1)
        all_fields: List[Field] = []
        if 1 in self.selected_tiers:
            for block in blocks:
                parser = self.standard_registry.get_parser(block.kind)
                if parser:
                    fields, findings, parse_diags = parser.parse(block)
                    all_fields.extend(fields)
                    record.fields.extend(fields)
                    for f in findings:
                        if self.scope.is_analyzer_permitted(f.extractor, f.tier):
                            record.add_finding(f)
                    record.diagnostics.extend(parse_diags)

        # Tier 2: Structural Fingerprints
        if 2 in self.selected_tiers and self.scope.is_analyzer_permitted("fingerprint_engine", 2):
            dqt_tables = []
            dht_tables = []
            subsampling = None
            restart_interval = None

            for u in units:
                if u.name == "DQT" and u.payload:
                    dqt_tables.extend(DqtExtractor.extract_from_dqt_payload(u.payload))
                elif u.name == "DHT" and u.payload:
                    dht_tables.extend(DhtExtractor.extract_from_dht_payload(u.payload))
                elif u.name.startswith("SOF") and u.payload:
                    subsampling = SubsamplingExtractor.extract_from_sof_payload(u.payload)
                elif u.name == "DRI" and u.payload and len(u.payload) >= 2:
                    restart_interval = int.from_bytes(u.payload[:2], "big")

            segment_sequence = SegmentOrderExtractor.extract_sequence(units)
            fp = CompositeFingerprintBuilder.build(
                format_name=detected.format_name,
                dqt_tables=dqt_tables,
                dht_tables=dht_tables,
                subsampling=subsampling,
                segment_sequence=segment_sequence,
                restart_interval=restart_interval,
            )

            record.add_finding(
                Finding(
                    name="encoder_composite_fingerprint",
                    value=fp.to_dict(),
                    tier=2,
                    extractor="composite_fingerprint_builder",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="fingerprint", extractor="composite_fingerprint_builder"),
                )
            )

            # Match against Reference Corpus (FR-3.7, FR-3.8)
            match_finding = FingerprintMatcher.match(fp, self.corpus)
            record.add_finding(match_finding)

        # Tier 3: Embedded Artefacts
        if 3 in self.selected_tiers and self.scope.is_analyzer_permitted("artefact_extractor", 3):
            # Check IFD1 thumbnail
            for b in blocks:
                if b.kind == "EXIF":
                    thumb = ThumbnailExtractor.extract_from_exif_block(b)
                    if thumb:
                        record.add_finding(
                            Finding(
                                name="exif_thumbnail_extracted",
                                value={"offset": thumb.offset, "length": thumb.length, "format": thumb.format_type},
                                tier=3,
                                extractor="thumbnail_extractor",
                                confidence=Confidence.OBSERVED,
                                caveat=None,
                                provenance=Provenance(source_layer="artefact", extractor="thumbnail_extractor", offset=thumb.offset, length=thumb.length),
                            )
                        )
                elif b.kind == "MPF":
                    mpf_images = MpfExtractor.extract_from_mpf_block(b)
                    if mpf_images:
                        record.add_finding(
                            Finding(
                                name="mpf_secondary_images",
                                value={"count": len(mpf_images)},
                                tier=3,
                                extractor="mpf_extractor",
                                confidence=Confidence.OBSERVED,
                                caveat=None,
                                provenance=Provenance(source_layer="artefact", extractor="mpf_extractor", offset=b.offset, length=b.length),
                            )
                        )

            # Trailing data
            for u in units:
                if u.name == "TRAILING_DATA":
                    trailing_info = TrailingDataExtractor.analyze(u, reader.get_all_bytes())
                    record.add_finding(
                        Finding(
                            name="trailing_data_detected",
                            value={
                                "offset": trailing_info.offset,
                                "length": trailing_info.length,
                                "shannon_entropy": trailing_info.shannon_entropy,
                                "detected_payload_type": trailing_info.detected_payload_type,
                                "preview_hex": trailing_info.preview_hex,
                            },
                            tier=3,
                            extractor="trailing_data_extractor",
                            confidence=Confidence.OBSERVED,
                            caveat=None,
                            provenance=Provenance(source_layer="artefact", extractor="trailing_data_extractor", offset=trailing_info.offset, length=trailing_info.length),
                        )
                    )

            # Container anomalies
            anomalies = ContainerAnomalyDetector.detect_anomalies(units, detected.format_name)
            for a in anomalies:
                record.add_finding(a)

        # Context for Tiers 4-7 Analysers
        ctx = AnalysisContext(
            file_path=working_path,
            reader=reader,
            format_name=detected.format_name,
            structural_units=units,
            metadata_blocks=blocks,
            fields=all_fields,
            existing_findings=record.findings,
            diagnostics=record.diagnostics,
            scope=self.scope,
            allow_network=self.allow_network,
            enable_ela=self.enable_ela,
        )

        # Execute permitted Tier 4-7 analysers & dynamic skills
        skill_reg = SkillRegistry.get_default()
        for tier in (4, 5, 6, 7):
            if tier in self.selected_tiers:
                for analyzer in self.analyzer_registry.get_analyzers_for_tier(tier):
                    if self.scope.is_analyzer_permitted(analyzer.id, tier):
                        try:
                            f_list, d_list = analyzer.analyze(ctx)
                            for f in f_list:
                                record.add_finding(f)
                            record.diagnostics.extend(d_list)
                        except Exception as e:
                            record.add_diagnostic(
                                level="error",
                                message=f"Analyzer {analyzer.id} failed: {e}",
                                source=analyzer.id,
                            )
                # Dynamic skills for this tier
                for skill in skill_reg.get_skills_for_tier(tier, detected.format_name):
                    try:
                        f_list, d_list = skill.analyze(ctx)
                        for f in f_list:
                            record.add_finding(f)
                        record.diagnostics.extend(d_list)
                    except Exception as e:
                        record.add_diagnostic(
                            level="warning",
                            message=f"Skill {skill.id} failed: {e}",
                            source=skill.id,
                        )

        # Update data stream hash on record
        for f in record.findings:
            if f.name == "image_data_stream_sha256":
                record.data_stream_sha256 = f.value

        # Compute Authenticity and Integrity Verdict
        verdict = AuthenticityEvaluator.evaluate(record)
        record.authenticity_verdict = verdict.to_dict()
        record.add_finding(
            Finding(
                name="authenticity_verdict",
                value=verdict.to_dict(),
                tier=6,
                extractor="authenticity_evaluator",
                confidence=(
                    Confidence.OBSERVED
                    if verdict.is_authentic is not None
                    else Confidence.INCONCLUSIVE
                ),
                caveat=(
                    "; ".join(verdict.forensic_caveats)
                    if verdict.forensic_caveats
                    else None
                ),
                provenance=Provenance(
                    source_layer="analyzer", extractor="authenticity_evaluator"
                ),
            )
        )

        # Publish VerdictEvaluatedEvent
        ForensicEventBus.get_default().publish(
            VerdictEvaluatedEvent(
                file_path=str(path),
                sha256=file_sha256,
                verdict_label=verdict.verdict_label,
                confidence_score=verdict.confidence_score,
                risk_level=verdict.risk_level,
            )
        )

        # GR-2.3: Re-verify evidence custody
        if self.evidence_store:
            self.evidence_store.verify_all_originals()

        if self.audit_logger:
            self.audit_logger.log(
                action="file_analysis_completed",
                outcome="SUCCESS",
                target_hash=file_sha256,
                details={"findings_count": len(record.findings)},
            )

        # Publish AnalysisCompletedEvent
        ForensicEventBus.get_default().publish(
            AnalysisCompletedEvent(
                file_path=str(path),
                sha256=file_sha256,
                mime_type=record.mime_type,
                findings_count=len(record.findings),
            )
        )

        return record
