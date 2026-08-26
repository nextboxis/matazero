"""Fingerprint reference corpus loader, manager, and learner per SRD FR-3.9 and ADR-007."""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CorpusEntry:
    entry_id: str
    device_model: str
    encoder_software: str
    processing_chain: str
    subsampling: str
    dqt_luminance_sample: List[int]
    segment_prefix: List[str]
    confidence: str = "indicative"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.entry_id,
            "device_model": self.device_model,
            "encoder_software": self.encoder_software,
            "processing_chain": self.processing_chain,
            "subsampling": self.subsampling,
            "dqt_luminance_sample": self.dqt_luminance_sample,
            "segment_prefix": self.segment_prefix,
            "confidence": self.confidence,
        }


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

        self.version = "2026.08.2-expanded"
        self.entries: List[CorpusEntry] = []
        self._load()
        self._load_user_corpus()

    def _load(self) -> None:
        if not self.corpus_path.exists():
            return
        try:
            with open(self.corpus_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.version = data.get("corpus_version", self.version)
                for item in data.get("entries", []):
                    self.entries.append(
                        CorpusEntry(
                            entry_id=item["id"],
                            device_model=item["device_model"],
                            encoder_software=item["encoder_software"],
                            processing_chain=item["processing_chain"],
                            subsampling=item["subsampling"],
                            dqt_luminance_sample=item["dqt_luminance_sample"],
                            segment_prefix=item.get("segment_prefix", []),
                            confidence=item.get("confidence", "indicative"),
                        )
                    )
        except Exception:
            pass

    def _load_user_corpus(self) -> None:
        user_p = self.get_user_corpus_path()
        if not user_p.exists():
            return
        try:
            with open(user_p, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("entries", []):
                    # Avoid duplicate IDs
                    if not any(e.entry_id == item["id"] for e in self.entries):
                        self.entries.append(
                            CorpusEntry(
                                entry_id=item["id"],
                                device_model=item["device_model"],
                                encoder_software=item["encoder_software"],
                                processing_chain=item["processing_chain"],
                                subsampling=item["subsampling"],
                                dqt_luminance_sample=item["dqt_luminance_sample"],
                                segment_prefix=item.get("segment_prefix", []),
                                confidence=item.get("confidence", "indicative"),
                            )
                        )
        except Exception:
            pass

    def add_user_entry(self, entry: CorpusEntry) -> None:
        """Append an entry to the user corpus on disk."""
        user_p = self.get_user_corpus_path()
        existing_entries = []
        if user_p.exists():
            try:
                with open(user_p, "r", encoding="utf-8") as f:
                    existing_entries = json.load(f).get("entries", [])
            except Exception:
                existing_entries = []

        # Update or append
        existing_entries = [e for e in existing_entries if e.get("id") != entry.entry_id]
        existing_entries.append(entry.to_dict())

        with open(user_p, "w", encoding="utf-8") as f:
            json.dump({"corpus_version": "user-custom", "entries": existing_entries}, f, indent=2)

        # Update runtime list
        self.entries = [e for e in self.entries if e.entry_id != entry.entry_id]
        self.entries.append(entry)
