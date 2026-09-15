"""Entropy-Guided Dictionary and Candidate Recovery Engine for Scrambled Images."""

from __future__ import annotations
import logging
from pathlib import Path
from typing import List, Optional, Tuple, Iterable, Generator

import numpy as np
from PIL import Image

from imgint.core.crypto.ciphers import cyrb128, Mulberry32Cipher

logger = logging.getLogger(__name__)

# Core candidate dictionary tailored for forensic triaging and common passwords
BUILTIN_CANDIDATE_LIST: List[str] = [
    # Defaults and common web scrambler keys
    "ABC123", "abc123", "123456", "12345678", "password", "Password", "admin", "secret",
    "1234", "0000", "1111", "9999", "12345", "qwerty", "test", "pass", "key",
    # System and user context
    "mata", "matazero", "Matazero", "MataZero", "imgint", "giridharan", "giri", "Giri",
    "nextboxis", "Nextboxis", "osint", "evidence", "forensics", "investigation",
    # Common words & numbers
    "image", "photo", "picture", "secure", "private", "hidden", "camera", "phone",
    "root", "master", "crypto", "cipher", "default", "welcome", "login",
    # Forensic PRNG seeds
    "seed:1260129352", "seed:0x4b1c0c48",
]


class DictionaryCracker:
    """Attempts dictionary recovery of scrambled images using spatial continuity heuristics."""

    PATCH_SIZE = 64  # 64x64 patch = 12,288 bytes; ultrafast to evaluate

    @classmethod
    def evaluate_candidate(cls, patch: np.ndarray, candidate: str) -> float:
        """Decrypts a sample patch and returns the spatial gradient variance.
        
        Natural image patches return ~5.0 - 30.0.
        Incorrect keys or noise return ~84.0 - 86.0.
        """
        h, w, c = patch.shape
        if candidate.startswith("seed:"):
            seed_val = candidate[5:]
            seed = int(seed_val, 16) if seed_val.lower().startswith("0x") else int(seed_val)
        else:
            seed = cyrb128(candidate)[0]

        num_bytes = h * w * c
        ks = Mulberry32Cipher.generate_keystream(seed, num_bytes).reshape((h, w, c))

        dec = patch ^ ks

        horiz = np.abs(dec.astype(np.int32)[:, 1:, :] - dec.astype(np.int32)[:, :-1, :]).mean()
        if h > 1:
            vert = np.abs(dec.astype(np.int32)[1:, :, :] - dec.astype(np.int32)[:-1, :, :]).mean()
            return float((horiz + vert) / 2.0)
        return float(horiz)


    @classmethod
    def crack(
        cls,
        image_path: str | Path,
        wordlist_path: Optional[str | Path] = None,
        extra_candidates: Optional[Iterable[str]] = None,
        max_candidates: int = 100_000,
    ) -> Optional[Tuple[str, float]]:
        """Cracks the password using dictionary heuristics.
        
        Returns (recovered_password, gradient_score) if found, or None.
        """
        p = Path(image_path)
        img = Image.open(p).convert("RGB")
        arr = np.array(img)

        # Extract contiguous rows across the full width to preserve keystream alignment
        h, w = arr.shape[:2]
        # Target ~10,000 - 30,000 bytes for fast yet highly accurate evaluation
        target_rows = max(2, min(h, 30_000 // (w * 3)))
        patch = arr[:target_rows, :, :3]

        candidates = cls._generate_candidate_stream(p, wordlist_path, extra_candidates)

        tested = 0
        for cand in candidates:
            tested += 1
            if tested > max_candidates:
                break
            score = cls.evaluate_candidate(patch, cand)
            if score < 35.0:  # Strong natural spatial continuity found!
                logger.info("Key successfully recovered: '%s' (score=%.2f) after %d trials", cand, score, tested)
                return cand, score

        return None


    @classmethod
    def _generate_candidate_stream(
        cls,
        target_path: Path,
        wordlist_path: Optional[str | Path] = None,
        extra_candidates: Optional[Iterable[str]] = None,
    ) -> Generator[str, None, None]:
        """Generates candidate passwords in priority order."""
        seen = set()

        # 1. Custom / metadata candidates from filename and file chunks
        file_stem = target_path.stem
        clean_stem = file_stem.replace("encrypted-", "").replace("scrambled-", "")
        context_candidates = [
            clean_stem,
            target_path.name,
            file_stem,
        ]

        # Check for deBG or other text chunks in the file
        try:
            raw = target_path.read_bytes()
            import re
            for m in re.finditer(b"deBG(.{4})(.{16})", raw):
                val = m.group(2).decode("latin1", errors="ignore")
                context_candidates.extend([val, val.lower(), val.upper()])
        except Exception:
            pass

        for c in context_candidates:
            if c and c not in seen:
                seen.add(c)
                yield c

        # 2. Extra candidates passed explicitly
        if extra_candidates:
            for c in extra_candidates:
                if c and c not in seen:
                    seen.add(c)
                    yield c

        # 3. Built-in candidates
        for c in BUILTIN_CANDIDATE_LIST:
            if c not in seen:
                seen.add(c)
                yield c

        # 4. User-supplied wordlist
        if wordlist_path:
            w_path = Path(wordlist_path)
            if w_path.exists():
                with open(w_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_cand = line.strip()
                        if line_cand and line_cand not in seen:
                            seen.add(line_cand)
                            yield line_cand

        # 5. Common 4-digit and 6-digit numeric sequences
        for num in range(1000):
            s = f"{num:04d}"
            if s not in seen:
                seen.add(s)
                yield s
