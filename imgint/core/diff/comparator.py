"""Forensic image differential comparator for comparing two evidence files."""

from __future__ import annotations
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.model.record import AnalysisRecord
from imgint.core.sandbox.process import SandboxRunner


@dataclass
class MetadataDiff:
    added: List[Dict[str, Any]] = field(default_factory=list)
    removed: List[Dict[str, Any]] = field(default_factory=list)
    modified: List[Dict[str, Any]] = field(default_factory=list)
    identical_count: int = 0


@dataclass
class ForensicDiffResult:
    target_a: str
    target_b: str
    format_a: str
    format_b: str
    size_a_bytes: int
    size_b_bytes: int
    size_delta_bytes: int
    sha256_match: bool
    data_hash_match: bool
    ahash_distance: Optional[int]
    dhash_distance: Optional[int]
    phash_distance: Optional[int]
    dqt_euclidean_distance: Optional[float]
    dqt_similarity_pct: Optional[float]
    metadata_diff: MetadataDiff
    pixel_diff: Optional[Dict[str, Any]]
    relationship_verdict: str
    summary_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ForensicComparator:
    """Compares two evidence images across structure, metadata, encoder DQT, and pixels."""

    @classmethod
    def compare(
        cls,
        target_a: str | Path,
        target_b: str | Path,
        pipeline: Optional[AnalysisPipeline] = None,
    ) -> ForensicDiffResult:
        p_a = Path(target_a)
        p_b = Path(target_b)

        if not pipeline:
            scope = AuthorizationScope.create_self_audit_scope()
            pipeline = AnalysisPipeline(scope=scope, selected_tiers={1, 2, 3, 4, 5, 6, 7})

        rec_a = pipeline.analyze_file(p_a)
        rec_b = pipeline.analyze_file(p_b)

        # 1. Container & Size
        size_a = p_a.stat().st_size
        size_b = p_b.stat().st_size
        size_delta = size_b - size_a
        sha_match = (rec_a.sha256 == rec_b.sha256)

        # 2. Cryptographic & Perceptual Hashes
        data_hash_a = next((f.value.get("pure_data_sha256") for f in rec_a.findings if f.name == "cryptographic_hashes" and isinstance(f.value, dict)), None)
        data_hash_b = next((f.value.get("pure_data_sha256") for f in rec_b.findings if f.name == "cryptographic_hashes" and isinstance(f.value, dict)), None)
        data_match = bool(data_hash_a and data_hash_b and data_hash_a == data_hash_b)

        phash_data_a = next((f.value for f in rec_a.findings if f.name == "perceptual_hashes" and isinstance(f.value, dict)), {})
        phash_data_b = next((f.value for f in rec_b.findings if f.name == "perceptual_hashes" and isinstance(f.value, dict)), {})

        def _hamming(h1_str: Optional[str], h2_str: Optional[str]) -> Optional[int]:
            if not h1_str or not h2_str:
                return None
            try:
                val1 = int(h1_str, 16)
                val2 = int(h2_str, 16)
                return bin(val1 ^ val2).count("1")
            except Exception:
                return None

        ahash_dist = _hamming(phash_data_a.get("ahash"), phash_data_b.get("ahash"))
        dhash_dist = _hamming(phash_data_a.get("dhash"), phash_data_b.get("dhash"))
        phash_dist = _hamming(phash_data_a.get("phash"), phash_data_b.get("phash"))

        # 3. Metadata Diff
        meta_diff = cls._diff_metadata(rec_a, rec_b)

        # 4. DQT Comparison
        dqt_dist, dqt_sim = cls._diff_dqt(rec_a, rec_b)

        # 5. Sandboxed Pixel Diff
        sandbox_res = SandboxRunner.run_decode_tasks(
            str(p_a), tasks=["pixel_diff"], compare_file_path=str(p_b)
        )
        pixel_diff = None
        if sandbox_res.get("success") and "tasks" in sandbox_res:
            pixel_diff = sandbox_res["tasks"].get("pixel_diff")

        # 6. Synthesize Relationship Verdict
        verdict, reasons = cls._evaluate_verdict(
            sha_match=sha_match,
            data_match=data_match,
            meta_diff=meta_diff,
            pixel_diff=pixel_diff,
            phash_dist=phash_dist,
            dqt_dist=dqt_dist,
        )

        return ForensicDiffResult(
            target_a=str(p_a),
            target_b=str(p_b),
            format_a=rec_a.mime_type,
            format_b=rec_b.mime_type,
            size_a_bytes=size_a,
            size_b_bytes=size_b,
            size_delta_bytes=size_delta,
            sha256_match=sha_match,
            data_hash_match=data_match,
            ahash_distance=ahash_dist,
            dhash_distance=dhash_dist,
            phash_distance=phash_dist,
            dqt_euclidean_distance=dqt_dist,
            dqt_similarity_pct=dqt_sim,
            metadata_diff=meta_diff,
            pixel_diff=pixel_diff,
            relationship_verdict=verdict,
            summary_reasons=reasons,
        )

    @classmethod
    def _diff_metadata(cls, rec_a: AnalysisRecord, rec_b: AnalysisRecord) -> MetadataDiff:
        fields_a = {f.name: f.value for f in rec_a.fields}
        fields_b = {f.name: f.value for f in rec_b.fields}

        added = [{"field": k, "value": fields_b[k]} for k in fields_b if k not in fields_a]
        removed = [{"field": k, "value": fields_a[k]} for k in fields_a if k not in fields_b]
        modified = []
        identical = 0

        for k in fields_a:
            if k in fields_b:
                if str(fields_a[k]) != str(fields_b[k]):
                    modified.append({"field": k, "value_a": fields_a[k], "value_b": fields_b[k]})
                else:
                    identical += 1

        return MetadataDiff(
            added=added,
            removed=removed,
            modified=modified,
            identical_count=identical,
        )

    @classmethod
    def _diff_dqt(cls, rec_a: AnalysisRecord, rec_b: AnalysisRecord) -> Tuple[Optional[float], Optional[float]]:
        # Find DQT tables from structural units
        dqt_a = None
        dqt_b = None
        for u in rec_a.structural_units:
            if u.name == "DQT" and u.payload:
                dqt_a = list(u.payload)
                break
        for u in rec_b.structural_units:
            if u.name == "DQT" and u.payload:
                dqt_b = list(u.payload)
                break

        if not dqt_a or not dqt_b:
            return None, None

        min_len = min(len(dqt_a), len(dqt_b))
        if min_len == 0:
            return None, None

        euclidean = math.sqrt(sum((dqt_a[i] - dqt_b[i]) ** 2 for i in range(min_len)))
        similarity = round(max(0.0, 100.0 / (1.0 + (euclidean / 50.0))), 1)
        return round(euclidean, 2), similarity

    @classmethod
    def _evaluate_verdict(
        cls,
        sha_match: bool,
        data_match: bool,
        meta_diff: MetadataDiff,
        pixel_diff: Optional[Dict[str, Any]],
        phash_dist: Optional[int],
        dqt_dist: Optional[float],
    ) -> Tuple[str, List[str]]:
        reasons = []

        if sha_match:
            reasons.append("Bitwise exact match: SHA-256 hashes are identical across all bytes.")
            return "EXACT_BITWISE_MATCH", reasons

        if data_match:
            reasons.append("Image data streams are bitwise identical; differences are confined strictly to metadata headers/tags.")
            return "METADATA_ONLY_MODIFICATION", reasons

        if pixel_diff and pixel_diff.get("identical_pixels"):
            reasons.append("Pixel values are 100% identical; differences exist only in container encapsulation, compression tables, or metadata.")
            return "CONTAINER_OR_RECOMPRESS_IDENTICAL_PIXELS", reasons

        if pixel_diff:
            altered_pct = pixel_diff.get("altered_pixels_pct", 0.0)
            ssim = pixel_diff.get("estimated_ssim", 0.0)

            if altered_pct <= 25.0 and ssim > 0.60:
                reasons.append(f"Localized pixel alteration detected: {altered_pct}% of pixels differ (SSIM: {ssim}). Potential localized edit, watermark insertion, or splicing.")
                return "LOCALIZED_TAMPERING_OR_EDIT", reasons
            elif ssim > 0.85 and (phash_dist is not None and phash_dist <= 10):
                reasons.append(f"Visually similar re-compression / re-encoding: SSIM is {ssim} and pHash Hamming distance is {phash_dist or 0}.")
                return "VISUALLY_SIMILAR_RECOMPRESSION", reasons
            else:
                reasons.append(f"Significant visual differences: {altered_pct}% pixels differ (SSIM: {ssim}, pHash distance: {phash_dist or 'N/A'}).")
                return "DISTINCT_OR_HEAVILY_ALTERED_IMAGES", reasons

        if phash_dist is not None:
            if phash_dist <= 5:
                reasons.append(f"Perceptual hashes are near-identical (Hamming distance: {phash_dist}).")
                return "PERCEPTUAL_NEAR_MATCH", reasons
            else:
                reasons.append(f"Perceptual hashes indicate different content (Hamming distance: {phash_dist}).")
                return "DISTINCT_IMAGES", reasons

        return "INCONCLUSIVE_DIFFERENCE", ["Insufficient comparative signals."]
