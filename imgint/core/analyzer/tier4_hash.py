"""Tier 4 Cryptographic and Perceptual Hashing per SRD FR-5.1 - FR-5.4."""

from __future__ import annotations
import hashlib
from typing import List, Tuple
from imgint.core.analyzer.base import Analyzer, AnalysisContext
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import Diagnostic
from imgint.core.sandbox.process import SandboxRunner


class HashingAnalyzer(Analyzer):
    """Computes file SHA-256, pure image data-stream SHA-256, and sandboxed perceptual hashes."""

    @property
    def id(self) -> str:
        return "tier4_hashing"

    @property
    def tier(self) -> int:
        return 4

    @property
    def requires_decode(self) -> bool:
        return False  # Main dispatcher runs in-process and delegates perceptual hashes to sandbox

    def analyze(self, ctx: AnalysisContext) -> Tuple[List[Finding], List[Diagnostic]]:
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        all_bytes = ctx.reader.get_all_bytes()

        # FR-5.1: SHA-256 of whole file
        file_sha256 = hashlib.sha256(all_bytes).hexdigest()
        findings.append(
            Finding(
                name="file_sha256",
                value=file_sha256,
                tier=4,
                extractor="hashing_analyzer",
                confidence=Confidence.OBSERVED,
                caveat=None,
                provenance=Provenance(source_layer="analyzer", extractor="hashing_analyzer"),
            )
        )

        # FR-5.2: SHA-256 of image data stream alone (excluding metadata)
        data_stream_hash = self._compute_pure_datastream_hash(ctx, all_bytes)
        if data_stream_hash:
            findings.append(
                Finding(
                    name="image_data_stream_sha256",
                    value=data_stream_hash,
                    tier=4,
                    extractor="hashing_analyzer",
                    confidence=Confidence.OBSERVED,
                    caveat=None,
                    provenance=Provenance(source_layer="analyzer", extractor="hashing_analyzer"),
                )
            )

        # FR-5.3 & FR-5.4: Perceptual hashes via sandboxed decode
        sandbox_res = SandboxRunner.run_decode_tasks(ctx.file_path, tasks=["phashes"])
        if sandbox_res.get("success") and "tasks" in sandbox_res:
            phashes = sandbox_res["tasks"].get("phashes", {})
            findings.append(
                Finding(
                    name="perceptual_hashes",
                    value={
                        "ahash": phashes.get("ahash"),
                        "dhash": phashes.get("dhash"),
                        "phash": phashes.get("phash"),
                        "corpus_internal_only": True,
                    },
                    tier=4,
                    extractor="sandboxed_perceptual_hasher",
                    confidence=Confidence.DERIVED,
                    caveat=(
                        "Perceptual hashes are strictly for corpus-internal near-duplicate clustering per FR-5.4. "
                        "They are invariant to small re-compressions and scaling, but cannot prove originality."
                    ),
                    provenance=Provenance(source_layer="sandbox", extractor="sandboxed_perceptual_hasher"),
                )
            )
        else:
            diagnostics.append(
                Diagnostic(
                    level="warning",
                    message=f"Sandboxed perceptual hashing failed: {sandbox_res.get('error')}",
                    source="hashing_analyzer",
                )
            )

        return findings, diagnostics

    def _compute_pure_datastream_hash(self, ctx: AnalysisContext, all_bytes: bytes) -> Optional[str]:
        if ctx.format_name == "JPEG":
            # Extract bytes from SOS to EOI
            sos_unit = next((u for u in ctx.structural_units if u.name == "SOS"), None)
            eoi_unit = next((u for u in ctx.structural_units if u.name == "EOI"), None)
            if sos_unit:
                start = sos_unit.data_offset + sos_unit.data_length
                end = eoi_unit.offset if eoi_unit else len(all_bytes)
                if 0 <= start < end <= len(all_bytes):
                    entropy_slice = all_bytes[start:end]
                    return hashlib.sha256(entropy_slice).hexdigest()

        elif ctx.format_name == "PNG":
            # Concatenate all IDAT chunks payload bytes
            idat_payloads = [u.payload for u in ctx.structural_units if u.name == "IDAT" and u.payload]
            if idat_payloads:
                combined = b"".join(idat_payloads)
                return hashlib.sha256(combined).hexdigest()

        return None
