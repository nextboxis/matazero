"""Reference corpus matcher with similarity scoring and thresholding per SRD FR-3.7, FR-3.8."""

from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from imgint.core.fingerprint.composite import EncoderFingerprint
from imgint.core.fingerprint.corpus import ReferenceCorpus, CorpusEntry
from imgint.core.model.finding import Finding, Confidence, Provenance


@dataclass
class MatchResult:
    matched: bool
    entry: Optional[CorpusEntry]
    similarity_score: float
    reason: str


class FingerprintMatcher:
    """Matches an extracted encoder fingerprint against the reference corpus."""

    SIMILARITY_THRESHOLD = 0.75

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

        # Get luminance table (table 0)
        lum_table = next((t for t in fingerprint.dqt_tables if t.table_id == 0), fingerprint.dqt_tables[0])
        lum_vals = lum_table.values

        best_entry: Optional[CorpusEntry] = None
        best_score = 0.0

        for entry in corpus.entries:
            score = cls._compute_table_similarity(lum_vals, entry.dqt_luminance_sample)

            # Bonus for matching subsampling
            if fingerprint.subsampling and fingerprint.subsampling.notation == entry.subsampling:
                score = min(1.0, score + 0.1)

            if score > best_score:
                best_score = score
                best_entry = entry

        if best_score >= cls.SIMILARITY_THRESHOLD and best_entry is not None:
            return Finding(
                name="encoder_attribution",
                value={
                    "device_model": best_entry.device_model,
                    "encoder_software": best_entry.encoder_software,
                    "processing_chain": best_entry.processing_chain,
                    "similarity_score": round(best_score, 3),
                    "corpus_version": corpus.version,
                },
                tier=2,
                extractor="fingerprint_matcher",
                confidence=Confidence.INDICATIVE,
                caveat=(
                    "Attribution is indicative and based on statistical resemblance to known encoder tables. "
                    "Software updates or third-party camera apps may alter quantization profiles."
                ),
                provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
                metadata={"corpus_version": corpus.version, "entry_id": best_entry.entry_id},
            )
        else:
            # FR-3.8: MUST report insufficient reference data rather than a low-confidence guess
            return Finding(
                name="encoder_attribution",
                value="insufficient reference data",
                tier=2,
                extractor="fingerprint_matcher",
                confidence=Confidence.INCONCLUSIVE,
                caveat=(
                    f"Highest similarity score ({round(best_score, 3)}) is below attribution threshold "
                    f"({cls.SIMILARITY_THRESHOLD}). No definitive encoder match found in corpus version {corpus.version}."
                ),
                provenance=Provenance(source_layer="fingerprint", extractor="fingerprint_matcher"),
                metadata={"corpus_version": corpus.version, "best_candidate_score": round(best_score, 3)},
            )

    @staticmethod
    def _compute_table_similarity(table1: List[int], table2: List[int]) -> float:
        if len(table1) < 64 or len(table2) < 64:
            return 0.0

        # Exact match
        if table1[:64] == table2[:64]:
            return 1.0

        # Normalized Euclidean distance over log-values
        diffs = []
        for i in range(64):
            v1 = max(1, table1[i])
            v2 = max(1, table2[i])
            diffs.append(abs(math.log(v1) - math.log(v2)))

        avg_diff = sum(diffs) / 64.0
        # Map average log diff to similarity [0, 1]
        similarity = math.exp(-avg_diff * 1.5)
        return similarity
