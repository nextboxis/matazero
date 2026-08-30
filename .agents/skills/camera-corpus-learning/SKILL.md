---
name: camera-corpus-learning
description: Guide for training, extracting, and registering new reference camera hardware fingerprints into the matazero corpus.
---

# Camera Hardware Corpus Training Guide

Use this skill when onboarding new camera models, smartphone sensors, or forensic reference test targets into the `matazero` hardware corpus.

## Extraction Procedure

1. **Capture Known-Good Reference Sample**:
   Ensure the image is taken directly from the physical hardware with original firmware and untouched by social media compression.

2. **Inspect Quantization & Segment Fingerprints**:
   ```bash
   python -m matazero probe ./reference_raw.jpg
   ```

3. **Register Hardware Profile**:
   Add the extracted DQT matrix, DHT Huffman tables, and segment order into `imgint/core/fingerprint/corpus.py` under the appropriate vendor identifier (`Canon`, `Nikon`, `Apple`, `Samsung`, `Sony`, `Google`).

4. **Verify Matching Rate**:
   ```bash
   python -m matazero corpus list
   python -m matazero analyze ./reference_raw.jpg -a
   ```
