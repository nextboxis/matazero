```text
 ███╗   ███╗ █████╗ ████████╗ █████╗ ███████╗███████╗██████╗  ██████╗ 
 ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
 ██╔████╔██║███████║   ██║   ███████║  ███╔╝ █████╗  ██████╔╝██║   ██║
 ██║╚██╔╝██║██╔══██║   ██║   ██╔══██║ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
 ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║███████╗███████╗██║  ██║╚██████╔╝
 ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
```

# matazero

> **Image Intelligence & Forensic Analysis Toolkit for OSINT and Digital Forensics**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![OPSEC](https://img.shields.io/badge/opsec-100%25%20offline-success.svg)](docs/SECURITY.md)
[![Governance](https://img.shields.io/badge/governance-hash--chained%20audit-blueviolet.svg)](docs/ETHICS.md)

---

## What is matazero?

**matazero** is an image forensics tool designed to recover every piece of data from an image file — including metadata, hardware encoder fingerprints, embedded previews, and hidden trailing payloads. It produces detailed forensic reports with confidence ratings and tamper analysis.

Even when social media platforms strip EXIF metadata, `matazero` analyzes the underlying JPEG compression structures (quantization tables, Huffman tables, subsampling ratios) to match the file against known camera hardware and editing software profiles.

```
┌───────────────────────────────┐
│     Evidence Image File       │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐      ┌───────────────────────────────┐
│       matazero Engine         │ ◄─── │      Authorization Scope      │
│  7-Tier Extraction Pipeline   │      │ Case ID · Legal Basis · HMAC  │
└───────────────┬───────────────┘      └───────────────────────────────┘
                │
        ┌───────┴───────────────────────────────┐
        ▼                                       ▼
┌───────────────────────────────┐       ┌───────────────────────────────┐
│   Evidence Dossier / Report   │       │     Audit Log Trail           │
│ Text · JSON · HTML · Hashes   │       │ Hash-Chained JSONL (SHA-256)  │
└───────────────────────────────┘       └───────────────────────────────┘
```

---

## Key Features

* **Attribution Without Metadata**: Reconstructs encoder profiles from raw quantization tables (`DQT`), Huffman tables (`DHT`), and chroma subsampling (`SOF`) against a database of 22+ smartphone, DSLR, social media, and AI generator fingerprints.
* **Camera Fingerprint Learning**: Learn and save custom device signatures directly into your local corpus (`matazero corpus learn`).
* **Interactive Standalone HTML Dossier**: Generates a self-contained, air-gapped HTML report (`-f html`) with an interactive SVG solar compass dial and structural byte map.
* **Automatic Payload Carver**: Detects and extracts hidden trailing archives (ZIP, RAR, 7z, TAR, GZ, Executables) appended past the image end marker (`-c` / `--carve`).
* **Multi-Format Container Walk**: Inspects segment structures for JPEG, PNG, TIFF/RAW (DNG, CR2, NEF, ARW, RAF), animated GIF, WebP, and ISO-BMFF (HEIC/AVIF).
* **Process Isolation Sandbox**: Quarantines pixel decoding inside a restricted subprocess to protect the host system against malicious image parser exploits.
* **Chain of Custody & Audit Logging**: Cryptographically verifies evidence integrity using SHA-256 hashing and append-only hash-chained audit logs.
* **100% Offline & Private**: Zero telemetry, zero cloud dependencies. Solar calculations and reverse geocoding run entirely local.

---

## The 7 Extraction Tiers

| Tier | Name | What it Extracts |
|:---:|---|---|
| **Tier 1** | **Metadata Blocks** | EXIF 2.32, XMP (safe entity-disabled), IPTC-IIM (8BIM), ICC color profiles, PNG text chunks, and C2PA authenticity manifests. |
| **Tier 2** | **Encoder Fingerprints** | JPEG `DQT` quantization tables, estimated quality factor (1–100), `DHT` Huffman tables, chroma subsampling (4:4:4, 4:2:2, 4:2:0), segment sequence, and hardware corpus matching. |
| **Tier 3** | **Embedded Artefacts** | IFD1 embedded thumbnails, MPF multi-picture frames, and trailing data past EOI/IEND with entropy analysis. |
| **Tier 4** | **Cryptographic Hashes** | Whole-file SHA-256, pure image data-stream SHA-256 (excludes metadata to detect re-tagging), and perceptual hashes (aHash, dHash, pHash). |
| **Tier 5** | **Geospatial & Temporal** | GPS coordinates, altitude, offline GeoNames reverse geocoding, NOAA solar azimuth/elevation chronolocation, and timestamp consistency checks. |
| **Tier 6** | **Forensic Indicators & Verdicts** | Ground-truth authenticity verdicts, timeline inversions (`ModifyDate` vs `DateTimeOriginal`), Error Level Analysis (ELA via `--ela`), and metadata absence analysis. |
| **Tier 7** | **Content-Derived Signals** | Sandboxed image dimensions, aspect ratio, dominant color palette approximation, and LSB entropy screening. |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/nextboxis/matazero.git
cd matazero

# Install in editable mode
pip install -e .
```

### Running the Tool

You can invoke `matazero` via any of the following:

```bash
# Recommended (works in any terminal)
python -m matazero --help

# Global CLI command (if Python Scripts is in your PATH)
matazero --help
```

---

## CLI Reference & Quickstart

```text
matazero <command> [options] [targets...]

Commands:
  scope       Create, validate, or display an authorization scope
  analyze     Run 7 extraction tiers over evidence files
  probe       Dump container segment and chunk structure with byte offsets
  corpus      Manage and inspect the reference encoder fingerprint corpus
  audit       Verify or export the tamper-evident audit log
  clean       Losslessly remove metadata in self-audit mode
  completion  Generate shell completion scripts (bash, zsh, fish)
```

### Common Usage Examples

```bash
# 1. Quick analysis on an image (Self-Audit mode for personal files)
python -m matazero analyze photo.jpg -a

# 2. Generate an interactive standalone HTML dossier
python -m matazero analyze photo.jpg -a -f html -o dossier.html

# 3. Output structured JSON for automation
python -m matazero analyze photo.jpg -a -f json -o output.json

# 4. Automatically carve hidden trailing ZIP/RAR/EXE payloads
python -m matazero analyze suspicious.jpg -a -c --carve-dir ./carved_files

# 5. Create an authorization scope for forensic custody
python -m matazero scope create -c "CASE-2026-01" -p "Forensic Ingest" -l "Warrant" -a "Lead Investigator" -o scope.json
python -m matazero scope validate scope.json

# 6. Run scoped analysis under legal custody
python -m matazero analyze evidence.jpg -s scope.json

# 7. Learn a new camera hardware fingerprint from a reference shot
python -m matazero corpus learn ref_shot.jpg -i canon_r5 -m "Canon EOS R5" -e "DIGIC X Hardware ISP"

# 8. List all registered device and platform profiles
python -m matazero corpus list

# 9. Probe container segments with exact byte offsets
python -m matazero probe photo.jpg

# 10. Verify audit log tamper-resistance
python -m matazero audit verify ./audit.jsonl

# 11. Losslessly strip metadata while preserving raw pixel streams
python -m matazero clean photo.jpg -o cleaned.jpg -c
```

---

## Short Flags Reference

| Subcommand | Short | Long Flag | Description |
| :--- | :--- | :--- | :--- |
| `analyze` | `-s` | `--scope` | Path to authorization scope JSON |
| `analyze` | `-a` | `--self-audit` | Run in self-audit mode without an external scope |
| `analyze` | `-f` | `--format` | Output format: `report`, `json`, `ndjson`, `table`, `html` |
| `analyze` | `-o` | `--out` | Write output to specified file |
| `analyze` | `-t` | `--tiers` | Comma-separated list of tiers to run (e.g. `1,2,3,4,7`) |
| `analyze` | `-e` | `--ela` | Enable Error Level Analysis (Tier 6) |
| `analyze` | `-c` | `--carve` | Automatically extract trailing payloads / archives |
| `analyze` | `-n` | `--allow-network` | Enable disclosed network lookups |
| `corpus learn` | `-i` | `--id` | Unique profile ID |
| `corpus learn` | `-m` | `--model` | Camera or device model description |
| `corpus learn` | `-e` | `--encoder` | Software or hardware encoder name |
| `scope create` | `-c` | `--case` | Case identifier |
| `scope create` | `-p` | `--purpose` | Investigation purpose |
| `scope create` | `-l` | `--legal-basis` | Lawful authority / warrant |
| `scope create` | `-a` | `--authorising-party` | Authorising party name/role |
| `scope create` | `-d` | `--days` | Scope validity window in days (default: 30) |
| `scope create` | `-o` | `--out` | Output path for scope JSON file |
| `scope create` | `-k` | `--secret` | HMAC secret key for signing |
| `scope validate`| `-k` | `--secret` | HMAC secret key for validation |
| `clean` | `-o` | `--out` | Destination path for cleaned file |
| `clean` | `-c` | `--commit` | Execute modification (dry-run without it) |

---

## Exit Codes

| Code | Status | Meaning |
|:---:|---|---|
| `0` | **Success** | Complete analysis finished successfully |
| `1` | **Runtime Error** | Unhandled execution exception |
| `2` | **Usage Error** | Invalid CLI options or argument syntax |
| `3` | **Unsupported Format** | File magic bytes not recognized |
| `4` | **Partial Success** | Batch completed with non-fatal diagnostics |
| `5` | **Budget Exceeded** | Resource/unit/depth safety limit exceeded |
| `6` | **Authorization Failure** | Missing, invalid, or expired authorization scope |
| `7` | **Custody Failure** | Evidence hash mismatch or broken audit chain |

---

## Ethical Boundaries

`matazero` includes code-level safeguards against surveillance abuse:

* ❌ **No Facial Recognition or Biometrics**
* ❌ **No Bulk Web Scraping or Social Media Crawling**
* ❌ **No Cross-Platform Identity Tracking**
* ❌ **No Real-Time Geolocation Tracking**
* ❌ **No External Hash Database Lookups**
* 🛡️ **Transparent Authenticity Analysis**: Authenticity assessments (`AUTHENTIC_CAMERA_CAPTURE`, `TAMPERED_TRAILING_PAYLOAD`, `AI_SYNTHETIC_GENERATION`, `UNVERIFIED_METADATA_STRIPPED`) are computed from verifiable structural indicators with mandatory confidence scores and caveats.

---

## Documentation

* [PRD (Product Requirements Document)](plan/PRD.md)
* [SRD (Software Requirements Document)](plan/SRD.md)
* [SRS (Software Requirements Specification)](plan/SRS.md)
* [Architecture & Decision Records](plan/ARCHITECTURE.md)
* [Security Policy & Threat Model](docs/SECURITY.md)
* [Ethics & Governance](docs/ETHICS.md)

---

## License

Distributed under the **Apache 2.0 License**. See [LICENSE](LICENSE) for details.
