"""Tier 6 Forensic Indicators with mandatory Caveat and Confidence per SRD FR-7.1 - FR-7.9."""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from imgint.core.analyzer.base import Analyzer, AnalysisContext
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import Diagnostic
from imgint.core.sandbox.process import SandboxRunner


class IndicatorsAnalyzer(Analyzer):
    """Evaluates consistency indicators without aggregating scores or declaring verdicts."""

    @property
    def id(self) -> str:
        return "tier6_indicators"

    @property
    def tier(self) -> int:
        return 6

    @property
    def requires_decode(self) -> bool:
        return False

    def analyze(self, ctx: AnalysisContext) -> Tuple[List[Finding], List[Diagnostic]]:
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        if not ctx.metadata_blocks:
            findings.append(
                Finding(
                    name="metadata_status",
                    value="metadata absent — normal for platform-distributed images",
                    tier=6,
                    extractor="indicators_analyzer",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="analyzer", extractor="indicators_analyzer"),
                )
            )

        dt_orig_str = ctx.get_field_value("DateTimeOriginal")
        dt_mod_str = ctx.get_field_value("ModifyDate") or ctx.get_field_value("DateTime")

        if dt_orig_str and dt_mod_str:
            dt_orig = self._parse_iso_or_exif(str(dt_orig_str))
            dt_mod = self._parse_iso_or_exif(str(dt_mod_str))
            if dt_orig and dt_mod:
                orig_cmp = dt_orig if dt_orig.tzinfo is not None else dt_orig.replace(tzinfo=timezone.utc)
                mod_cmp = dt_mod if dt_mod.tzinfo is not None else dt_mod.replace(tzinfo=timezone.utc)
                if mod_cmp < orig_cmp:
                    findings.append(
                        Finding(
                            name="indicator_timeline_inversion",
                            value={
                                "datetime_original": dt_orig_str,
                                "modify_date": dt_mod_str,
                                "condition": "ModifyDate precedes DateTimeOriginal",
                            },
                            tier=6,
                            extractor="indicators_analyzer",
                            confidence=Confidence.INDICATIVE,
                            caveat=(
                                "ModifyDate precedes DateTimeOriginal. Common false positives include camera clock "
                                "adjustments, batch export script bugs, or timezone conversion anomalies."
                            ),
                            provenance=Provenance(source_layer="analyzer", extractor="indicators_analyzer"),
                        )
                    )

        thumb_finding = ctx.get_finding("exif_thumbnail_extracted")
        if thumb_finding:
            findings.append(
                Finding(
                    name="indicator_embedded_thumbnail_present",
                    value="Embedded thumbnail found in IFD1",
                    tier=6,
                    extractor="indicators_analyzer",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="analyzer", extractor="indicators_analyzer"),
                )
            )

        if ctx.enable_ela:
            sandbox_res = SandboxRunner.run_decode_tasks(ctx.file_path, tasks=["ela"])
            if sandbox_res.get("success") and "tasks" in sandbox_res:
                ela_data = sandbox_res["tasks"].get("ela", {})
                findings.append(
                    Finding(
                        name="indicator_error_level_analysis",
                        value=ela_data,
                        tier=6,
                        extractor="sandboxed_ela",
                        confidence=Confidence.INDICATIVE,
                        caveat=(
                            "CRITICAL CAVEAT: Error Level Analysis (ELA) indicates compression error rate differences. "
                            "High ELA variance naturally occurs at high-contrast edges, fine textures, text, and flat backgrounds. "
                            "It MUST NEVER be interpreted as proof of splicing or manipulation without independent corroboration."
                        ),
                        provenance=Provenance(source_layer="sandbox", extractor="sandboxed_ela"),
                    )
                )

        return findings, diagnostics

    def _parse_iso_or_exif(self, s: str) -> Optional[datetime]:
        s = s.strip()
        if not s:
            return None
        try:
            iso_s = s.replace("Z", "+00:00") if s.endswith("Z") else s
            return datetime.fromisoformat(iso_s)
        except Exception:
            pass

        clean = s.split(".")[0]
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(clean, fmt)
            except Exception:
                pass
        return None
