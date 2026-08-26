# matazero (imgint)

> **Evidence-Grade, Ethical Image Intelligence Toolkit for OSINT and Digital Forensics**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-21%2F21%20passing-brightgreen.svg)](tests/)
[![Security Architecture](https://img.shields.io/badge/sandbox-isolated%20decode-orange.svg)](docs/SECURITY.md)
[![Governance](https://img.shields.io/badge/governance-hash--chained%20audit-blueviolet.svg)](docs/ETHICS.md)
[![Offline First](https://img.shields.io/badge/opsec-100%25%20offline-success.svg)](docs/SECURITY.md)

---

## 1. Overview

**matazero** extracts every recoverable signal from an image file — metadata blocks, encoder fingerprints, embedded artefacts, trailing data, and content-derived analytics — and correlates them into an evidence-grade report with per-finding provenance, confidence ratings, and contextual caveats.

Built for verification journalists, DFIR analysts, security researchers, and privacy-conscious individuals, **matazero** bridges the gap between raw metadata extraction and responsible forensic interpretation.

```
┌───────────────────────────────┐
│     Lawfully Held Image       │
└───────────────┬───────────────┘
                │
                ▼
┌───────────────────────────────┐      ┌───────────────────────────────┐
│       matazero Pipeline       │ ◄─── │      Authorization Scope      │
│  7-Tier Extraction & Analysis │      │ Case ID · Legal Basis · Hash  │
└───────────────┬───────────────┘      └───────────────────────────────┘
                │
        ┌───────┴───────────────────────────────┐
        ▼                                       ▼
┌───────────────────────────────┐       ┌───────────────────────────────┐
│    Evidence-Grade Report      │       │     Append-Only Audit Log     │
│ Confidence · Caveats · Proof  │       │ Hash-Chained JSONL (SHA-256)  │
└───────────────────────────────┘       └───────────────────────────────┘
```

---

## 2. Key Differentiators

* **Attribution from Stripped Images (Tier 2)**: Major platforms strip EXIF metadata on upload. `matazero` inspects surviving structural signatures — Quantization Tables (`DQT`), Huffman Tables (`DHT`), chroma subsampling (`SOF`), and segment ordering — matching them against a reference corpus to identify camera models and re-encoding software.
* **Structural Sandbox Isolation (ADR-004)**: Pixel decoding is quarantined in an isolated, resource-capped subprocess. Host systems remain protected against image decoder CVEs (such as `libwebp` CVE-2023-4863 and `libjpeg-turbo` exploits).
* **Mandatory Uncertainty & No Verdicts (ADR-008)**: Forensics tools that output boolean `"manipulated: true"` cause severe harm. `matazero` requires confidence levels (`observed`, `derived`, `indicative`, `inconclusive`) and contextual caveat text on every derived assertion.
* **Cryptographic Chain of Custody (GR-2.x)**: Input files are hashed on ingest and kept strictly read-only. Operations run on isolated working copies, and original hashes are verified on completion (Exit code 7 on mismatch).
* **100% Offline OPSEC (ADR-005)**: Zero telemetry, zero external network requests by default. Reverse geocoding runs entirely offline against a local bundled dataset (`geonames_offline.json`).

---

## 3. The 7 Extraction Tiers

| Tier | Category | Key Signals Extracted & Analyzed |
|:---:|---|---|
| **Tier 1** | **Metadata Blocks** | EXIF 2.32 (IFD0, SubIFD, GPS, Interop, IFD1), safe entity-disabled XMP RDF/XML, IPTC-IIM (8BIM), multi-part ICC profiles, C2PA/JUMBF manifests, and PNG native text chunks (`tEXt`, `zTXt`, `iTXt`, `tIME`, `pHYs`). |
| **Tier 2** | **Encoder Fingerprints** | JPEG `DQT` quantization table extraction, IJG quality estimation (1–100), `DHT` Huffman table classification (default vs. custom/optimized), chroma subsampling (4:4:4, 4:2:2, 4:2:0), segment sequence, and reference corpus matching. |
| **Tier 3** | **Embedded Artefacts** | IFD1 thumbnail extraction, aspect ratio mismatch (crop indicator), MPF secondary pictures / depth maps, and trailing data detection past `FFD9`/`IEND` with Shannon entropy & signature classification (ZIP, RAR, EXE, script). |
| **Tier 4** | **Cryptographic Hashes** | Whole-file SHA-256, pure image datastream SHA-256 (excluding metadata blocks to detect metadata-only edits), and perceptual hashes (aHash, dHash, pHash) flagged as corpus-internal only. |
| **Tier 5** | **Geospatial & Temporal** | Signed decimal GPS degrees, altitude, DOP, offline reverse geocoding via bundled GeoNames index, NOAA solar azimuth/elevation chronolocation, and temporal cross-checks (`DateTimeOriginal` vs. `GPSDateStamp`, timezone vs. longitude). |
| **Tier 6** | **Forensic Indicators** | Metadata timeline contradictions, quantization inconsistency, Error Level Analysis (ELA, opt-in via `--ela`), and metadata absence reporting (normal platform behavior vs anomaly). Refuses score aggregation. |
| **Tier 7** | **Content-Derived Signals** | Sandboxed pixel decoding for image dimensions, aspect ratio, dominant color palette extraction, and LSB entropy screening. |

---

## 4. Installation

```bash
# Clone the repository
git clone https://github.com/nextboxis/matazero.git
# Install in editable mode
pip install -e .

# Or install optional test dependencies
pip install -e ".[test]"
```

### Running the Tool:

You can run **matazero** in any of the following ways:

```bash
# 1. As a Python module (Recommended, works in any terminal environment)
python -m matazero --help
python -m mata --help

# 2. As a direct script
python matazero.py --help

# 3. As a global CLI binary (ensure Python Scripts folder is in your PATH)
matazero --help
mata --help
```

---

## 5. Quickstart & CLI Reference

```
matazero <command> [flags] [targets...]

Commands:
  scope       Create, validate, or display an authorization scope
  analyze     Run 7 extraction tiers over evidence files
  probe       Dump container segment and chunk structure with byte offsets
  corpus      Manage and inspect the reference encoder fingerprint corpus
  audit       Verify or export the tamper-evident audit log
  clean       Losslessly remove metadata in self-audit mode
  completion  Generate shell completion scripts (bash, zsh, fish)
```

### 5.1 Command Overview

```bash
matazero scope       # Create, validate, or display an authorization scope
matazero analyze     # Run 7 extraction tiers over evidence files
matazero probe       # Dump container segment and chunk structure with byte offsets
matazero corpus      # List known camera profiles or learn from new reference images
matazero audit       # Verify or export the tamper-evident audit log
matazero clean       # Losslessly remove metadata in self-audit mode
matazero completion  # Generate shell completion scripts (bash, zsh, fish)
```

### 5.2 Quick Examples & Short Flags

```bash
# 1. Create and validate an authorization scope (Short flags: -c, -p, -l, -a, -o)
python -m matazero scope create -c "CASE-001" -p "Forensic Ingest" -l "Warrant" -a "Lead" -o scope.json
python -m matazero scope validate scope.json

# 2. Run full 7-tier forensic analysis with active scope (-s)
python -m matazero analyze evidence.jpg -s scope.json

# 3. Generate an interactive standalone offline HTML Dossier (-f html -o report.html)
python -m matazero analyze evidence.jpg -a -f html -o report.html

# 4. Analyze and automatically carve hidden trailing payloads / ZIP archives (-c / --carve)
python -m matazero analyze suspicious.jpg -a -c --carve-dir ./carved_payloads

# 5. Inspect or expand the reference camera / encoder corpus
python -m matazero corpus list
python -m matazero corpus learn reference_shot.jpg -i my_camera_id -m "Sony Alpha A7 IV" -e "Sony BIONZ XR"

# 6. Probe container structure with exact byte offsets
python -m matazero probe evidence.jpg

# 7. Verify the cryptographic hash chain of the audit trail
python -m matazero audit verify ./audit.jsonl

# 8. Losslessly strip metadata while preserving raw image pixels (-o out, -c commit)
python -m matazero clean personal.jpg -o cleaned.jpg -c
```

## 6. Short Flags & Options Reference

| Subcommand | Short Flag | Long Flag | Description |
| :--- | :--- | :--- | :--- |
| `analyze` | `-s` | `--scope` | Path to authorization scope JSON |
| `analyze` | `-a` | `--self-audit` | Operate in self-audit mode without an external scope |
| `analyze` | `-f` | `--format` | Output format (`report`, `json`, `ndjson`, `table`, `html`) |
| `analyze` | `-o` | `--out` | Write output to destination file |
| `analyze` | `-t` | `--tiers` | Comma-separated list of tiers to run (e.g. `1,2,3,4,7`) |
| `analyze` | `-e` | `--ela` | Enable Error Level Analysis (Tier 6) |
| `analyze` | `-c` | `--carve` | Automatically carve trailing payloads / archives |
| `analyze` | `-n` | `--allow-network` | Enable disclosed network lookups (GR-4.1) |
| `corpus learn` | `-i` | `--id` | Unique identifier for new device profile |
| `corpus learn` | `-m` | `--model` | Camera or device model description |
| `corpus learn` | `-e` | `--encoder` | Software or hardware encoder pipeline name |
| `scope create` | `-c` | `--case` | Case ID identifier |
| `scope create` | `-p` | `--purpose` | Forensic investigation purpose |
| `scope create` | `-l` | `--legal-basis` | Legal basis or warrant authority |
| `scope create` | `-a` | `--authorising-party` | Name/role of authorising party |
| `scope create` | `-d` | `--days` | Scope validity duration in days (default: 30) |
| `scope create` | `-o` | `--out` | Output path for scope JSON file |
| `scope create` | `-k` | `--secret` | HMAC secret key for cryptographic signing |
| `clean` | `-o` | `--out` | Output path for cleaned file |
| `clean` | `-c` | `--commit` | Required flag to execute file modification |

---

## 6. Exit Codes

| Code | Status | Meaning |
|:---:|---|---|
| `0` | **Success** | Complete analysis success |
| `1` | **Runtime Error** | Unhandled execution error |
| `2` | **Usage Error** | Invalid CLI arguments or flags |
| `3` | **Unsupported Format** | Unsupported container magic bytes |
| `4` | **Partial Success** | Batch completed with non-fatal diagnostics |
| `5` | **Budget Exceeded** | Resource/unit/depth budget exceeded |
| `6` | **Authorization Failure** | Missing, invalid, or expired authorization scope |
| `7` | **Custody Failure** | Evidence hash mismatch or broken audit chain |

---

## 7. Refused Capabilities & Governance Boundaries

Per **GR-3.1 through GR-3.8** and `docs/ETHICS.md`, the following mass surveillance capabilities are **permanently refused**:

* ❌ **No Face Recognition or Biometric Identification** (GDPR Art. 9).
* ❌ **No Bulk Web / Platform Scraping**.
* ❌ **No Automated Identity Correlation Across Platforms**.
* ❌ **No Real-Time Location Tracking**.
* ❌ **No External Hash Database Lookups (PhotoDNA, etc.)**.
* 🛡️ **Authenticity & Integrity Verdicts**: Ground-truth structural verdicts (`AUTHENTIC_CAMERA_CAPTURE`, `TAMPERED_TRAILING_PAYLOAD`, `AI_SYNTHETIC_GENERATION`, `UNVERIFIED_METADATA_STRIPPED`) are computed transparently from hardware quantization profiles, container markers, C2PA claims, and tamper indicators with mandatory confidence scores and caveats.

---

## 8. Running Tests

Execute the comprehensive 29-test suite covering governance, parsing, fingerprinting, sandboxing, payload carving, C2PA, HTML dossier, authenticity verdicts, and CLI workflows:

```bash
python -m pytest tests/ -v
```

---

## 9. Documentation

* [PRD (Product Requirements Document)](plan/PRD.md)
* [SRD (Software Requirements Document)](plan/SRD.md)
* [SRS (Software Requirements Specification)](plan/SRS.md)
* [Architecture & ADRs](plan/ARCHITECTURE.md)
* [Security Policy & Threat Model](docs/SECURITY.md)
* [Ethics & Governance Model](docs/ETHICS.md)

---

## 10. License

Licensed under the **Apache 2.0 License**. See [LICENSE](LICENSE) for details.
