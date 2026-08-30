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
            ctx.file_path,
            tasks=[
                "dimensions",
                "dominant_colors",
                "entropy",
                "fft_frequency",
                "ghost",
                "cfa",
                "copymove",
            ],
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

        # 2D FFT Frequency & Synthetic Grid Anomaly Screening
        if "fft_frequency" in tasks:
            fft_data = tasks["fft_frequency"]
            findings.append(
                Finding(
                    name="fft_synthetic_artifact_screening",
                    value=fft_data,
                    tier=7,
                    extractor="sandboxed_fft_analyzer",
                    confidence=Confidence.INDICATIVE if fft_data.get("synthetic_grid_artifact") else Confidence.OBSERVED,
                    caveat=(
                        "2D FFT power spectrum analyzes periodic frequency spikes. High peak ratios (>18.0) indicate "
                        "generative AI upsampling checkerboard grid patterns or regular geometric screen moiré."
                    ),
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_fft_analyzer"),
                )
            )

        # JPEG Ghost & Double Compression Splicing Analysis
        if "ghost" in tasks:
            ghost_data = tasks["ghost"]
            findings.append(
                Finding(
                    name="jpeg_ghost_splicing_analysis",
                    value=ghost_data,
                    tier=7,
                    extractor="sandboxed_ghost_analyzer",
                    confidence=Confidence.DERIVED,
                    caveat=(
                        "JPEG Ghost evaluation computes localized compression error surfaces. Multi-modal quality variance "
                        "indicates composite image splicing from a different JPEG donor source."
                    ),
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_ghost_analyzer"),
                )
            )

        # CFA (Color Filter Array) Bayer Demosaicing Inconsistency Analysis
        if "cfa" in tasks:
            cfa_data = tasks["cfa"]
            is_hw = cfa_data.get("is_hardware_sensor_consistent", False)
            findings.append(
                Finding(
                    name="cfa_bayer_demosaicing_analysis",
                    value=cfa_data,
                    tier=7,
                    extractor="sandboxed_cfa_analyzer",
                    confidence=Confidence.OBSERVED if is_hw else Confidence.INDICATIVE,
                    caveat=(
                        "CFA Bayer analysis measures second-order green channel interpolation covariance. Physical camera "
                        "sensors produce periodic demosaicing patterns, whereas synthetic AI images and digital paintings lack them."
                    ),
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_cfa_analyzer"),
                )
            )

        # Copy-Move & Clone-Stamp Forgery Detection
        if "copymove" in tasks:
            copymove_data = tasks["copymove"]
            is_cloned = copymove_data.get("copy_move_detected", False)
            findings.append(
                Finding(
                    name="copymove_cloning_analysis",
                    value=copymove_data,
                    tier=7,
                    extractor="sandboxed_copymove_detector",
                    confidence=Confidence.DERIVED if is_cloned else Confidence.OBSERVED,
                    caveat=(
                        "Copy-move detector clusters matching spatial block feature vectors. Identical shift vector clusters "
                        "indicate deliberate clone-stamping or object duplication."
                    ),
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_copymove_detector"),
                )
            )

        return findings, diagnostics
