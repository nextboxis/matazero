"""Reference corpus matcher with multi-signal disambiguation per SRD FR-3.7, FR-3.8."""

from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from imgint.core.fingerprint.composite import EncoderFingerprint
from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.model.finding import Finding, Confidence, Provenance


WEIGHT_DQT_LUMINANCE = 0.45
WEIGHT_DQT_CHROMINANCE = 0.15
WEIGHT_SEGMENT_ORDER = 0.15
WEIGHT_SUBSAMPLING = 0.10
WEIGHT_DHT_TYPE = 0.10
WEIGHT_SOF_TYPE = 0.05

SIMILARITY_THRESHOLD = 0.75
AMBIGUITY_MARGIN = 0.02


@dataclass
class CandidateMatch:
    """A scored candidate from the reference corpus."""
    entry: CorpusEntry
    composite_score: float
    dqt_luminance_score: float
    dqt_chrominance_score: float
    segment_order_score: float
    subsampling_score: float
    dht_score: float
    sof_score: float


class FingerprintMatcher:
    """Matches an extracted encoder fingerprint against the reference corpus
    using multi-signal weighted scoring and collision disambiguation."""

    @classmethod
    def match(
        cls, fingerprint: EncoderFingerprint, corpus: ReferenceCorpus
    ) -> Finding:
        if not fingerprint.dqt_tables:
            return Finding(
                name="encoder_attribution",
                value="insufficient reference data (no DQT tables)",
                tier=2,
                extractor="fingerprint_matcher",
                confidence=Confidence.INCONCLUSIVE,
                caveat="Attribution requires quantization tables which are absent in this file.",
                provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
                metadata={"corpus_version": corpus.version},
            )

        lum_table = next(
            (t for t in fingerprint.dqt_tables if t.table_id == 0),
            fingerprint.dqt_tables[0],
        )
        lum_vals = lum_table.values

        chrom_table = next(
            (t for t in fingerprint.dqt_tables if t.table_id == 1),
            None,
        )
        chrom_vals = chrom_table.values if chrom_table else None

        file_sof_type = cls._extract_sof_type(fingerprint.segment_sequence)

        file_has_optimized_dht = any(
            not h.is_standard for h in fingerprint.dht_tables
        ) if fingerprint.dht_tables else False

        file_primary_app = cls._extract_primary_app_marker(fingerprint.segment_sequence)

        candidates: List[CandidateMatch] = []
        for entry in corpus.entries:
            candidate = cls._score_candidate(
                entry=entry,
                lum_vals=lum_vals,
                chrom_vals=chrom_vals,
                fingerprint=fingerprint,
                file_sof_type=file_sof_type,
                file_has_optimized_dht=file_has_optimized_dht,
                file_primary_app=file_primary_app,
            )
            candidates.append(candidate)

        candidates.sort(key=lambda c: c.composite_score, reverse=True)

        best = candidates[0] if candidates else None
        if best is None or best.composite_score < SIMILARITY_THRESHOLD:
            best_score = best.composite_score if best else 0.0
            return Finding(
                name="encoder_attribution",
                value="insufficient reference data",
                tier=2,
                extractor="fingerprint_matcher",
                confidence=Confidence.INCONCLUSIVE,
                caveat=(
                    f"Highest composite similarity score ({round(best_score, 3)}) is below attribution threshold "
                    f"({SIMILARITY_THRESHOLD}). No definitive encoder match found in corpus version {corpus.version}."
                ),
                provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
                metadata={
                    "corpus_version": corpus.version,
                    "best_candidate_score": round(best_score, 3),
                },
            )

        runners_up = [
            c for c in candidates[1:]
            if c.composite_score >= (best.composite_score - AMBIGUITY_MARGIN)
            and c.composite_score >= SIMILARITY_THRESHOLD
        ]

        if runners_up:
            all_candidates_info = [cls._candidate_info(best)] + [
                cls._candidate_info(c) for c in runners_up
            ]
            categories = list({c.entry.category for c in [best] + runners_up})

            return Finding(
                name="encoder_attribution",
                value={
                    "ambiguous": True,
                    "best_match": {
                        "device_model": best.entry.device_model,
                        "encoder_software": best.entry.encoder_software,
                        "processing_chain": best.entry.processing_chain,
                        "category": best.entry.category,
                        "composite_score": round(best.composite_score, 3),
                    },
                    "candidates": all_candidates_info,
                    "collision_categories": categories,
                    "corpus_version": corpus.version,
                },
                tier=2,
                extractor="fingerprint_matcher",
                confidence=Confidence.INCONCLUSIVE,
                caveat=(
                    f"Multiple corpus entries match with similar scores "
                    f"(spread: {round(best.composite_score - runners_up[-1].composite_score, 3)}). "
                    f"Categories involved: {', '.join(categories)}. "
                    "Use EXIF metadata, segment order, or visual inspection for definitive attribution."
                ),
                provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
                metadata={
                    "corpus_version": corpus.version,
                    "candidate_count": len(all_candidates_info),
                    "collision_group": [c.entry.entry_id for c in [best] + runners_up],
                },
            )

        return Finding(
            name="encoder_attribution",
            value={
                "device_model": best.entry.device_model,
                "encoder_software": best.entry.encoder_software,
                "processing_chain": best.entry.processing_chain,
                "category": best.entry.category,
                "similarity_score": round(best.composite_score, 3),
                "corpus_version": corpus.version,
            },
            tier=2,
            extractor="fingerprint_matcher",
            confidence=Confidence.INDICATIVE,
            caveat=(
                "Attribution is indicative and based on multi-signal statistical resemblance "
                "(DQT luminance/chrominance, segment order, subsampling, DHT, SOF type). "
                "Software updates or third-party camera apps may alter quantization profiles."
            ),
            provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
            metadata={
                "corpus_version": corpus.version,
                "entry_id": best.entry.entry_id,
                "score_breakdown": {
                    "dqt_luminance": round(best.dqt_luminance_score, 3),
                    "dqt_chrominance": round(best.dqt_chrominance_score, 3),
                    "segment_order": round(best.segment_order_score, 3),
                    "subsampling": round(best.subsampling_score, 3),
                    "dht_type": round(best.dht_score, 3),
                    "sof_type": round(best.sof_score, 3),
                },
            },
        )

    @classmethod
    def _score_candidate(
        cls,
        entry: CorpusEntry,
        lum_vals: List[int],
        chrom_vals: Optional[List[int]],
        fingerprint: EncoderFingerprint,
        file_sof_type: Optional[str],
        file_has_optimized_dht: bool,
        file_primary_app: Optional[str],
    ) -> CandidateMatch:
        """Compute multi-signal weighted composite score for a single candidate."""
        dqt_lum_score = cls._compute_table_similarity(lum_vals, entry.dqt_luminance_sample)

        dqt_chrom_score = 0.5
        if chrom_vals and entry.dqt_chrominance_sample:
            dqt_chrom_score = cls._compute_table_similarity(chrom_vals, entry.dqt_chrominance_sample)

        seg_score = cls._compute_segment_order_score(
            fingerprint.segment_sequence, entry.segment_prefix
        )

        sub_score = 0.5
        if fingerprint.subsampling:
            sub_score = 1.0 if fingerprint.subsampling.notation == entry.subsampling else 0.0

        dht_score = 0.5
        signals = entry.disambiguation_signals or {}
        entry_dht_type = signals.get("dht_type")
        if entry_dht_type and fingerprint.dht_tables:
            entry_is_optimized = (entry_dht_type == "optimized")
            dht_score = 1.0 if (file_has_optimized_dht == entry_is_optimized) else 0.0

        sof_score = 0.5
        entry_sof_type = signals.get("sof_type")
        if entry_sof_type and file_sof_type:
            sof_score = 1.0 if file_sof_type == entry_sof_type else 0.0

        composite = (
            WEIGHT_DQT_LUMINANCE * dqt_lum_score
            + WEIGHT_DQT_CHROMINANCE * dqt_chrom_score
            + WEIGHT_SEGMENT_ORDER * seg_score
            + WEIGHT_SUBSAMPLING * sub_score
            + WEIGHT_DHT_TYPE * dht_score
            + WEIGHT_SOF_TYPE * sof_score
        )

        return CandidateMatch(
            entry=entry,
            composite_score=composite,
            dqt_luminance_score=dqt_lum_score,
            dqt_chrominance_score=dqt_chrom_score,
            segment_order_score=seg_score,
            subsampling_score=sub_score,
            dht_score=dht_score,
            sof_score=sof_score,
        )

    @staticmethod
    def _compute_table_similarity(table1: List[int], table2: List[int]) -> float:
        """Compute similarity between two quantization tables using log-space Euclidean distance."""
        if len(table1) < 64 or len(table2) < 64:
            return 0.0

        if table1[:64] == table2[:64]:
            return 1.0

        diffs = []
        for i in range(64):
            v1 = max(1, table1[i])
            v2 = max(1, table2[i])
            diffs.append(abs(math.log(v1) - math.log(v2)))

        avg_diff = sum(diffs) / 64.0
        similarity = math.exp(-avg_diff * 1.5)
        return similarity

    @staticmethod
    def _compute_segment_order_score(
        file_sequence: List[str], entry_prefix: List[str]
    ) -> float:
        """Score how well the file's segment order matches the corpus entry's prefix pattern."""
        if not entry_prefix or not file_sequence:
            return 0.5

        max_match = min(len(file_sequence), len(entry_prefix))
        matched = 0
        for i in range(max_match):
            if i < len(file_sequence) and file_sequence[i] == entry_prefix[i]:
                matched += 1
            else:
                break

        if max_match == 0:
            return 0.5

        return matched / max_match

    @staticmethod
    def _extract_sof_type(segment_sequence: List[str]) -> Optional[str]:
        """Extract the SOF marker type (SOF0, SOF2, etc.) from segment sequence."""
        for seg in segment_sequence:
            if seg.startswith("SOF"):
                return seg
        return None

    @staticmethod
    def _extract_primary_app_marker(segment_sequence: List[str]) -> Optional[str]:
        """Extract the first APPn marker from the segment sequence."""
        for seg in segment_sequence:
            if seg.startswith("APP"):
                return seg
        return None

    @staticmethod
    def _candidate_info(candidate: CandidateMatch) -> Dict[str, Any]:
        """Format a candidate for inclusion in the finding value."""
        return {
            "entry_id": candidate.entry.entry_id,
            "device_model": candidate.entry.device_model,
            "category": candidate.entry.category,
            "composite_score": round(candidate.composite_score, 3),
            "score_breakdown": {
                "dqt_luminance": round(candidate.dqt_luminance_score, 3),
                "dqt_chrominance": round(candidate.dqt_chrominance_score, 3),
                "segment_order": round(candidate.segment_order_score, 3),
                "subsampling": round(candidate.subsampling_score, 3),
            },
        }
