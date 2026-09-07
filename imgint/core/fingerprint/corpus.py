"""Fingerprint reference corpus loader, manager, and learner per SRD FR-3.9 and ADR-007."""

from __future__ import annotations
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Valid JPEG marker names for segment_prefix validation
VALID_JPEG_MARKERS = frozenset({
    "SOI", "EOI", "SOS", "DQT", "DHT", "DRI",
    "SOF0", "SOF1", "SOF2", "SOF3", "SOF5", "SOF6", "SOF7",
    "SOF9", "SOF10", "SOF11", "SOF13", "SOF14", "SOF15",
    "APP0", "APP1", "APP2", "APP3", "APP4", "APP5", "APP6", "APP7",
    "APP8", "APP9", "APP10", "APP11", "APP12", "APP13", "APP14", "APP15",
    "COM", "RST0", "RST1", "RST2", "RST3", "RST4", "RST5", "RST6", "RST7",
})


@dataclass
class CorpusEntry:
    entry_id: str
    device_model: str
    encoder_software: str
    processing_chain: str
    subsampling: str
    dqt_luminance_sample: List[int]
    segment_prefix: List[str]
    category: str = "unknown"
    dqt_chrominance_sample: Optional[List[int]] = None
    disambiguation_signals: Optional[Dict[str, Any]] = None
    known_collisions: Optional[List[str]] = None
    confidence: str = "indicative"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.entry_id,
            "device_model": self.device_model,
            "encoder_software": self.encoder_software,
            "processing_chain": self.processing_chain,
            "category": self.category,
            "subsampling": self.subsampling,
            "dqt_luminance_sample": self.dqt_luminance_sample,
            "segment_prefix": self.segment_prefix,
            "confidence": self.confidence,
        }
        if self.dqt_chrominance_sample is not None:
            d["dqt_chrominance_sample"] = self.dqt_chrominance_sample
        if self.disambiguation_signals is not None:
            d["disambiguation_signals"] = self.disambiguation_signals
        if self.known_collisions is not None:
            d["known_collisions"] = self.known_collisions
        return d

    @staticmethod
    def validate_entry_data(item: Dict[str, Any]) -> Optional[str]:
        """Validate a raw corpus entry dict. Returns error message or None if valid."""
        entry_id = item.get("id", "")
        if not entry_id or not isinstance(entry_id, str):
            return "Missing or empty 'id' field"

        dqt = item.get("dqt_luminance_sample")
        if not isinstance(dqt, list):
            return f"Entry '{entry_id}': dqt_luminance_sample must be a list"
        if len(dqt) != 64:
            return f"Entry '{entry_id}': dqt_luminance_sample must have exactly 64 values, got {len(dqt)}"
        for i, v in enumerate(dqt):
            if not isinstance(v, int) or v < 1 or v > 255:
                return f"Entry '{entry_id}': dqt_luminance_sample[{i}] = {v} is invalid (must be int 1-255)"

        dqt_chrom = item.get("dqt_chrominance_sample")
        if dqt_chrom is not None:
            if not isinstance(dqt_chrom, list) or len(dqt_chrom) != 64:
                return f"Entry '{entry_id}': dqt_chrominance_sample must have exactly 64 values"
            for i, v in enumerate(dqt_chrom):
                if not isinstance(v, int) or v < 1 or v > 255:
                    return f"Entry '{entry_id}': dqt_chrominance_sample[{i}] = {v} is invalid (must be int 1-255)"

        seg = item.get("segment_prefix", [])
        if seg:
            for marker in seg:
                if marker not in VALID_JPEG_MARKERS:
                    return f"Entry '{entry_id}': invalid segment marker '{marker}'"

        for required_field in ("device_model", "encoder_software", "processing_chain", "subsampling"):
            if not item.get(required_field):
                return f"Entry '{entry_id}': missing required field '{required_field}'"

        return None


def _parse_entry(item: Dict[str, Any]) -> CorpusEntry:
    """Parse a raw dict into a CorpusEntry dataclass."""
    return CorpusEntry(
        entry_id=item["id"],
        device_model=item["device_model"],
        encoder_software=item["encoder_software"],
        processing_chain=item["processing_chain"],
        subsampling=item["subsampling"],
        dqt_luminance_sample=item["dqt_luminance_sample"],
        segment_prefix=item.get("segment_prefix", []),
        category=item.get("category", "unknown"),
        dqt_chrominance_sample=item.get("dqt_chrominance_sample"),
        disambiguation_signals=item.get("disambiguation_signals"),
        known_collisions=item.get("known_collisions"),
        confidence=item.get("confidence", "indicative"),
    )


class ReferenceCorpus:
    """Manages the versioned reference corpus of encoder fingerprints."""

    @staticmethod
    def get_user_corpus_path() -> Path:
        p = Path.home() / ".matazero" / "user_corpus.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def __init__(self, corpus_path: Optional[str | Path] = None):
        if corpus_path:
            self.corpus_path = Path(corpus_path)
        else:
            # Default to bundled package seed data
            self.corpus_path = Path(__file__).parent.parent / "data" / "corpus_seed.json"

        self.version = "2026.09.1-disambiguated"
        self.entries: List[CorpusEntry] = []
        self._load_errors: List[str] = []
        self._load()
        self._load_user_corpus()

    def _load(self) -> None:
        if not self.corpus_path.exists():
            logger.warning("Corpus seed file not found: %s", self.corpus_path)
            return
        try:
            with open(self.corpus_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.version = data.get("corpus_version", self.version)
                for item in data.get("entries", []):
                    error = CorpusEntry.validate_entry_data(item)
                    if error:
                        self._load_errors.append(f"Seed corpus: {error}")
                        logger.warning("Skipping malformed corpus entry: %s", error)
                        continue
                    self.entries.append(_parse_entry(item))
        except json.JSONDecodeError as e:
            msg = f"Failed to parse corpus seed JSON: {e}"
            self._load_errors.append(msg)
            logger.error(msg)
        except (KeyError, TypeError) as e:
            msg = f"Corpus seed data structure error: {e}"
            self._load_errors.append(msg)
            logger.error(msg)

    def _load_user_corpus(self) -> None:
        """Load user corpus entries, overriding seed entries with matching IDs."""
        user_p = self.get_user_corpus_path()
        if not user_p.exists():
            return
        try:
            with open(user_p, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("entries", []):
                    error = CorpusEntry.validate_entry_data(item)
                    if error:
                        self._load_errors.append(f"User corpus: {error}")
                        logger.warning("Skipping malformed user corpus entry: %s", error)
                        continue
                    entry = _parse_entry(item)
                    # User entries OVERRIDE seed entries with the same ID
                    self.entries = [e for e in self.entries if e.entry_id != entry.entry_id]
                    self.entries.append(entry)
        except json.JSONDecodeError as e:
            msg = f"Failed to parse user corpus JSON: {e}"
            self._load_errors.append(msg)
            logger.error(msg)
        except (KeyError, TypeError) as e:
            msg = f"User corpus data structure error: {e}"
            self._load_errors.append(msg)
            logger.error(msg)

    def add_user_entry(self, entry: CorpusEntry) -> None:
        """Append an entry to the user corpus on disk."""
        user_p = self.get_user_corpus_path()
        existing_entries: List[Dict[str, Any]] = []
        if user_p.exists():
            try:
                with open(user_p, "r", encoding="utf-8") as f:
                    existing_entries = json.load(f).get("entries", [])
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.warning("Could not read existing user corpus, starting fresh: %s", e)
                existing_entries = []

        # Update or append
        existing_entries = [e for e in existing_entries if e.get("id") != entry.entry_id]
        existing_entries.append(entry.to_dict())

        with open(user_p, "w", encoding="utf-8") as f:
            json.dump({"corpus_version": "user-custom", "entries": existing_entries}, f, indent=2)

        # Update runtime list (user entries override)
        self.entries = [e for e in self.entries if e.entry_id != entry.entry_id]
        self.entries.append(entry)

    def get_entry_by_id(self, entry_id: str) -> Optional[CorpusEntry]:
        """Look up a corpus entry by its unique ID."""
        for e in self.entries:
            if e.entry_id == entry_id:
                return e
        return None

    def get_entries_by_category(self, category: str) -> List[CorpusEntry]:
        """Return all entries matching a given category."""
        return [e for e in self.entries if e.category == category]

    @property
    def load_errors(self) -> List[str]:
        """Returns any validation or parse errors encountered during loading."""
        return list(self._load_errors)

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, entry_id: str) -> bool:
        return any(e.entry_id == entry_id for e in self.entries)

    def __repr__(self) -> str:
        return f"ReferenceCorpus(version={self.version!r}, entries={len(self.entries)})"
