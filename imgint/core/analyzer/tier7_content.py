"""Tier 7 Content-Derived Signals executed in sandbox per SRD FR-8.1 - FR-8.4."""

from __future__ import annotations
from typing import List, Tuple
from imgint.core.analyzer.base import Analyzer, AnalysisContext
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import Diagnostic
from imgint.core.sandbox.process import SandboxRunner


class ContentAnalyzer(Analyzer):
    """Executes sandboxed pixel decode to extract dominant colors, dimensions, and LSB entropy."""

    @property
    def id(self) -> str:
        return "tier7_content"

    @property
    def tier(self) -> int:
        return 7

    @property
    def requires_decode(self) -> bool:
        return True

    def analyze(self, ctx: AnalysisContext) -> Tuple[List[Finding], List[Diagnostic]]:
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        sandbox_res = SandboxRunner.run_decode_tasks(
            ctx.file_path, tasks=["dimensions", "dominant_colors", "entropy"]
        )

        if not sandbox_res.get("success"):
            diagnostics.append(
                Diagnostic(
                    level="warning",
                    message=f"Sandboxed content analysis failed: {sandbox_res.get('error')}",
                    source="content_analyzer",
                )
            )
            return findings, diagnostics

        tasks = sandbox_res.get("tasks", {})

        # FR-8.4: Dimensions and aspect ratio
        if "dimensions" in tasks:
            dims = tasks["dimensions"]
            findings.append(
                Finding(
                    name="image_dimensions",
                    value=dims,
                    tier=7,
                    extractor="sandboxed_pixel_decoder",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_pixel_decoder"),
                )
            )

        # FR-8.4: Dominant colors
        if "dominant_colors" in tasks:
            colors = tasks["dominant_colors"]
            findings.append(
                Finding(
                    name="dominant_color_palette",
                    value=colors,
                    tier=7,
                    extractor="sandboxed_pixel_decoder",
                    confidence=Confidence.DERIVED,
                    caveat="Dominant color approximation computed from downsampled spatial distribution.",
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_pixel_decoder"),
                )
            )

        # FR-8.3: LSB Entropy screening
        if "entropy" in tasks:
            entropy_data = tasks["entropy"]
            findings.append(
                Finding(
                    name="lsb_entropy_screening",
                    value=entropy_data,
                    tier=7,
                    extractor="sandboxed_pixel_decoder",
                    confidence=Confidence.INDICATIVE,
                    caveat=(
                        "LSB entropy screening is a statistical indicator only. High LSB density naturally occurs in "
                        "noisy camera sensors, high-ISO captures, or textured gradients, and does not prove steganography."
                    ),
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_pixel_decoder"),
                )
            )

        return findings, diagnostics
