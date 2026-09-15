# 🔬 matazero Sample CLI Cookbook & Evidence Guide

This directory provides reference authorization scopes, sample evidence workflows, and copy-pasteable CLI recipes for **matazero** (courtroom-grade, offline-first digital image forensics & OSINT toolkit).

---

## 📁 Directory Assets

| File | Type | Description |
| :--- | :---: | :--- |
| [`sample_scope.json`](./sample_scope.json) | Legal Scope | Pre-configured HMAC-hashed authorization scope for test/lab investigations. |
| [`README.md`](./README.md) | Documentation | This guide: comprehensive sample CLI workflows, options, and recipes. |

---

## ⚠️ Important CLI Syntax Rule

> [!IMPORTANT]
> **Subcommand Requirement**: Always include the command verb (`encrypt`, `decrypt`, `stego`, `analyze`, `scan`). Invoking `matazero <image> ...` without a subcommand defaults to `analyze`, which does not accept encryption/decryption flags like `-p` / `--password` or `--container`.

---

## 🚀 Step-by-Step Sample CLI Workflows

All sample commands below use the reference evidence file `IMG20260901143431.jpg` present in the workspace root. Run these commands directly from the repository root.

---

### 1. System Health & Diagnostics
Verify Python runtime, memory safety limits, sandboxed worker isolation, local Ollama vision models, and offline GeoNames databases:
```bash
matazero doctor
```

---

### 2. Fast 1-Command Evidence Triage (`scan`)
Recursively scan evidence files, extract metadata across all tiers, and render a self-contained, dark-mode interactive HTML Case Dossier:
```bash
# Scan current directory and generate an HTML dossier
matazero scan . -o case_dossier.html

# Scan with an explicit legal scope file
matazero scan . -s samples/sample_scope.json -o case_dossier.html
```

---

### 3. Deep 7-Tier Forensic Analysis (`analyze`)
Inspect container byte-structures, EXIF/XMP metadata, DQT quantization fingerprints, and pixel integrity:
```bash
# Full 7-tier deep forensic tree breakdown
matazero analyze IMG20260901143431.jpg -a --deep

# Executive visual summary dashboard in terminal
matazero analyze IMG20260901143431.jpg -a --summary

# Error Level Analysis (ELA) for detecting JPEG re-compression tampering
matazero analyze IMG20260901143431.jpg -a --ela

# Export forensic findings to structured JSON
matazero analyze IMG20260901143431.jpg -a --format json -o analysis_output.json
```

---

### 4. Image Encryption & Forensic Packaging (`encrypt`)
Scramble image rasters to protect sensitive evidence during transit, or encapsulate raw files into tamper-evident authenticated containers:

```bash
# A. Scramble image pixels using Mulberry32 PRNG stream cipher
matazero encrypt IMG20260901143431.jpg -p "Case#2026-Secret" -m mulberry32 -o encrypted-IMG20260901143431.png -a

# B. Scramble image using 2D Arnold Cat Map chaotic matrix permutation
matazero encrypt IMG20260901143431.jpg -p "VaultKey#99" -m chaos -o chaos-IMG20260901143431.png -a

# C. Package entire evidence file into an authenticated AES-256-GCM container (.mataenc)
matazero encrypt IMG20260901143431.jpg -p "LegalHold#2026" --container -o evidence-IMG20260901143431.mataenc -a
```

---

### 5. Forensic Decryption & Seed Recovery (`decrypt`)
De-scramble obfuscated rasters using known passkeys, direct 32-bit seeds, or automated entropy-guided dictionary cracking:

```bash
# A. Decrypt image using password/passkey
matazero decrypt encrypted-IMG20260901143431.png -p "Case#2026-Secret" -o decrypted-IMG20260901143431.png -a

# B. Decrypt directly using recovered 32-bit PRNG seed (1006181859 for 'Case#2026-Secret')
matazero decrypt encrypted-IMG20260901143431.png --seed 1006181859 -o decrypted-IMG20260901143431.png -a

# C. Automated entropy-guided dictionary cracking for unknown passkeys
matazero decrypt encrypted-IMG20260901143431.png --brute-force -w ./wordlist.txt -a

# D. Decrypt an authenticated AES-256-GCM forensic container (.mataenc)
matazero decrypt evidence-IMG20260901143431.mataenc -p "LegalHold#2026" -o recovered-IMG20260901143431.jpg -a
```

---

### 6. Steganography Inspection, Injection & Extraction (`stego`)
Detect hidden payloads, perform multi-channel bitplane slicing, or embed and recover covert forensic messages:

```bash
# A. Embed encrypted message into RGB Least-Significant Bitplanes (LSB)
matazero stego IMG20260901143431.jpg --inject "Forensic finding: verified unaltered camera sensor" -p "StegoSecret#2026" -o stego-IMG20260901143431.png -a

# B. Extract covert LSB message from suspect carrier image
matazero stego stego-IMG20260901143431.png --extract -p "StegoSecret#2026" -a

# C. Multi-channel bitplane slicing (planes 0-7) and Chi-Square Pair-of-Values test
matazero stego IMG20260901143431.jpg -a --save-bitplanes ./bitplane_slices/

# D. Output stego metrics in structured JSON format
matazero stego IMG20260901143431.jpg -a -f json -o stego_report.json
```

---

### 7. Tampering & Image Comparison (`diff`)
Compare two images to highlight differences in structure, metadata, DQT quantization tables, and pixel SSIM delta:
```bash
# Compare authentic original against decrypted or suspect derivative
matazero diff IMG20260901143431.jpg decrypted-IMG20260901143431.png -f table

# Machine-readable diff output
matazero diff IMG20260901143431.jpg decrypted-IMG20260901143431.png -f json -o diff_report.json
```

---

### 8. Offline AI Vision Interrogation (`ask`)
Interrogate evidence images using your local Ollama vision model without sending bytes to third-party cloud services:
```bash
# High-accuracy multimodal interrogation
matazero ask IMG20260901143431.jpg "Identify vehicles, license plates, badges, and readable text" -m llama3.2-vision

# Detect synthetic/AI generation markers
matazero ask IMG20260901143431.jpg "Are there lighting, reflection, or anatomical anomalies indicating AI generation?" -m llama3.2-vision
```

---

### 9. Geolocation & Solar Chronolocation (`locate`)
Extract GPS coordinates, reverse-geocode against offline database, and verify daylight angles:
```bash
# Geolocation summary and solar position verification
matazero locate IMG20260901143431.jpg -a

# Export locations across an evidence set to GeoJSON / Leaflet Map
matazero locate . -a -r -f geojson -o case_locations.geojson
```

---

### 10. Multi-Asset Timeline Reconstruction (`timeline`)
Reconstruct chronological order across evidence from multiple cameras and estimate clock drift:
```bash
matazero timeline . -a -r -f plaso -o case_timeline.jsonl
```

---

### 11. Camera Hardware Fleet Clustering (`cluster`)
Cluster photos by camera make/model, DQT table fingerprints, or GPS proximity to identify outlier/anomalous photos:
```bash
matazero cluster . -a -r -k camera --outliers
```

---

### 12. Legal Chain of Custody & Scope Verification (`scope`)
Ensure strict legal admissibility with cryptographically signed authorization scopes:
```bash
# Create a new signed authorization scope
matazero scope create -c "CASE-2026-001" -p "Digital evidence analysis" -l "Court Order #42" -a "Lead Forensics Officer" -d 30 -o my_scope.json

# Validate an existing authorization scope file
matazero scope validate samples/sample_scope.json
```

---

## 📌 Common CLI Flags Summary

| Flag | Long Flag | Description |
| :---: | :--- | :--- |
| `-a` | `--self-audit` | Self-audit mode for personal files (bypasses scope requirement) |
| `-s` | `--scope <path>` | Path to authorization scope JSON for legal custody chain |
| `-o` | `--out <path>` | Write results or carved output to file |
| `-f` | `--format <fmt>` | Format: `report`, `dashboard`, `deep`, `json`, `ndjson`, `table`, `html` |
| `-p` | `--password <pwd>`| Passphrase for encryption, decryption, container, or stego |
| `-m` | `--method <algo>` | Cipher algorithm (`mulberry32`, `chaos`, `aes-256-gcm`, `auto`) |
| | `--container` | Wrap file into an authenticated AES-256-GCM `.mataenc` container |
| | `--seed <val>` | Direct 32-bit PRNG seed (decimal or hex e.g. `1260129352`) |
| | `--brute-force` | Automated entropy-guided dictionary cracking |
| `-w` | `--wordlist <path>`| Custom wordlist for dictionary cracking |
| | `--inject <text>` | Embed text into image LSBs |
| | `--extract` | Extract hidden LSB or trailing payload |
| | `--save-bitplanes`| Directory to dump 8-bitplane slices per channel |
| `-r` | `--recursive` | Recurse through subdirectories |
| `-j` | `--jobs <n>` | Worker thread count for batch processing |
