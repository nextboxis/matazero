<div align="center">

```text
 ███╗   ███╗ █████╗ ████████╗ █████╗ ███████╗███████╗██████╗  ██████╗ 
 ████╗ ████║██╔══██╗╚══██╔══╝██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
 ██╔████╔██║███████║   ██║   ███████║  ███╔╝ █████╗  ██████╔╝██║   ██║
 ██║╚██╔╝██║██╔══██║   ██║   ██╔══██║ ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
 ██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║███████╗███████╗██║  ██║╚██████╔╝
 ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ 
```

# matazero
### Evidence-Grade Image Intelligence & Forensic Toolkit for OSINT

[![Release](https://img.shields.io/badge/release-v2.1.0-blue.svg?style=flat-square)](https://github.com/nextboxis/matazero/releases)
[![Tests](https://img.shields.io/badge/tests-34%20passed-success.svg?style=flat-square&logo=pytest)](tests/)
[![Container](https://img.shields.io/badge/docker-ghcr.io-blueviolet.svg?style=flat-square&logo=docker)](https://github.com/users/nextboxis/packages?repo_name=matazero)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-informational.svg?style=flat-square&logo=python)](https://python.org)
[![Air-Gapped OPSEC](https://img.shields.io/badge/opsec-100%25%20offline-success.svg?style=flat-square)](docs/SECURITY.md)
[![Tamper Proof](https://img.shields.io/badge/audit-SHA--256%20hash--chain-orange.svg?style=flat-square)](docs/ETHICS.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg?style=flat-square)](LICENSE)

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-the-7-extraction-tiers">7 Extraction Tiers</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-docker--container-package">Docker</a> •
  <a href="#-quickstart--usage">Quickstart</a> •
  <a href="#-cli-reference">CLI Reference</a> •
  <a href="#-testing--quality-assurance">Testing</a> •
  <a href="#-guarantees">Guarantees</a>
</p>

---

</div>

## 🔭 Overview

**matazero** is an evidence-grade, air-gapped forensic analysis engine engineered for **digital forensics investigators**, **OSINT analysts**, and **security researchers**. It extracts every recoverable trace from an image: deep metadata blocks, camera hardware compression signatures, hidden trailing payloads, and synthetic generation indicators.

### Why matazero?

* **Attribution Even When Metadata is Stripped**: Social platforms (Twitter, Telegram, WhatsApp) aggressively strip EXIF tags. `matazero` inspects the underlying **JPEG compression matrix** — Quantization Tables (`DQT`), Huffman tables (`DHT`), chroma subsampling (`SOF`), and segment prefix orders — to mathematically attribute images to specific camera hardware ISPs, editing suites, or Generative AI pipelines.
* **100% Offline & Private**: Zero telemetry. Zero remote cloud calls. Local offline solar chronolocation, local reverse geocoding, and local vision model interrogation (via Ollama).
* **Forensic Chain of Custody**: Every finding carries verifiable provenance and confidence ratings. Case operations produce tamper-evident, append-only **SHA-256 hash-chained audit trails**.

```
                           ┌───────────────────────────────┐
                           │      Evidence Image File      │
                           └───────────────┬───────────────┘
                                           │
                                           ▼
┌───────────────────────────────┐      ┌───────────────────────────────┐
│      Authorization Scope      │ ───► │        matazero Engine        │
│  Case ID · Legal Basis · HMAC │      │  7-Tier Extraction Pipeline   │
└───────────────────────────────┘      └───────────────┬───────────────┘
                                                       │
                               ┌───────────────────────┴───────────────────────┐
                               ▼                                               ▼
               ┌───────────────────────────────┐               ┌───────────────────────────────┐
               │   Interactive Case Dossier    │               │    Tamper-Evident Audit Log   │
               │ Dark HTML · JSON · Leaflet 3D │               │  Hash-Chained JSONL (SHA-256) │
               └───────────────────────────────┘               └───────────────────────────────┘
```

---

## 🔬 The 7 Extraction Tiers

| Tier | Layer | Capabilities & Forensic Artifacts |
|:---:|:---|:---|
| **Tier 1** | **Metadata Blocks** | EXIF 2.32, XMP (entity-disabled parser), IPTC-IIM (8BIM), ICC color profiles, PNG text chunks, and C2PA cryptographic authenticity manifests. |
| **Tier 2** | **Encoder Fingerprints** | JPEG `DQT` quantization tables, quality factor estimation (1–100), `DHT` Huffman optimization, chroma subsampling (4:4:4, 4:2:2, 4:2:0), and multi-signal corpus matching. |
| **Tier 3** | **Embedded Artefacts** | IFD1 embedded thumbnails, MPF multi-picture stereo frames, and trailing data past EOI/IEND markers with Shannon entropy density analysis. |
| **Tier 4** | **Cryptographic Hashes** | Whole-file SHA-256, pure pixel bitstream SHA-256 (excludes metadata to detect re-tagging), and perceptual hashes (aHash, dHash, pHash). |
| **Tier 5** | **Geospatial & Temporal** | GPS coordinate parsing, altitude, offline GeoNames reverse geocoding, NOAA solar azimuth/elevation chronolocation, and timeline consistency audits. |
| **Tier 6** | **Indicators & Verdicts** | Deterministic authenticity classification (`AUTHENTIC`, `TAMPERED`, `AI_SYNTHETIC`), timeline inversions (`ModifyDate` < `DateTimeOriginal`), and Error Level Analysis (ELA). |
| **Tier 7** | **Content & AI Analysis** | JPEG Ghost double-compression detection, CFA Bayer demosaicing periodicity (physical sensor vs AI model), copy-move clone detection, and local Ollama vision AI. |

---

## ⚡ Installation

### Quick Automated One-Liner

<table>
<tr>
<td><b>Linux, Kali Linux & macOS</b></td>
<td><b>Windows (PowerShell)</b></td>
</tr>
<tr>
<td>

```bash
git clone https://github.com/nextboxis/matazero.git
cd matazero && chmod +x install.sh && ./install.sh
```

</td>
<td>

```powershell
git clone https://github.com/nextboxis/matazero.git
cd matazero; .\install.ps1
```

</td>
</tr>
</table>

---

### Option 1: Install from Source

```bash
# Clone the repository
git clone https://github.com/nextboxis/matazero.git
cd matazero

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\Activate.ps1    # Windows PowerShell

# Install dependencies and CLI package
pip install -r requirements.txt
pip install -e .
```

---

### Option 2: Direct Install via Git

```bash
pip install git+https://github.com/nextboxis/matazero.git
```

---

### Option 3: Zero-Install Standalone Execution

Run directly via the Python runtime without registering system binaries:

```bash
pip install -r requirements.txt
python -m matazero --help
```

---

## 🐳 Docker / Container Package

Pre-built, lightweight container images are published directly to the **[GitHub Container Registry](https://github.com/users/nextboxis/packages?repo_name=matazero)** (`ghcr.io`):

```bash
# Pull the latest container
docker pull ghcr.io/nextboxis/matazero:latest

# Run interactive health check
docker run --rm ghcr.io/nextboxis/matazero:latest doctor

# Analyze an evidence folder (mount current directory to /evidence)
docker run --rm -v "${PWD}:/evidence" ghcr.io/nextboxis/matazero:latest scan . -o dossier.html
```

---

## 🚀 Quickstart & Usage

### 1. System Health Check
Verify Python runtime, subprocess sandboxing, local Ollama models, and storage:
```bash
matazero doctor
```

### 2. 1-Command Evidence Triage (`scan`)
Auto-triage an entire folder of photos with live progress bars and generate an interactive dark-mode HTML case dossier:
```bash
matazero scan ./case_photos -o case_dossier.html
```

### 3. Executive Visual Dashboard
Run self-audit mode on an image to view camera attribution, GPS, and authenticity verdicts:
```bash
matazero photo.jpg -a
```

### 4. Deep Forensic Tree Inspection
Inspect all 7 tiers with precise tag names, byte offsets, and hex locations:
```bash
matazero photo.jpg -a --deep
```

### 5. Offline AI Visual Interrogation (`ask`)
Ask natural-language questions about an image using local Ollama vision models (zero cloud requests):
```bash
matazero ask crime_scene.jpg "Transcribe all visible license plates, badges, and street signs"
```

### 6. Detect Splicing & Clones (Copy-Move & JPEG Ghost)
Analyze compression error surfaces and duplicate regions:
```bash
matazero analyze forged.jpg -a --ela
matazero stego suspect.png -a --save-bitplanes ./bitplane_slices
```

### 7. Chronolocation & Forensic Geolocation
Calculate sun position and verify photo timestamp against physical daylight angles:
```bash
matazero locate photo.jpg -a
```

---

## 🐧 Local AI Vision on Kali Linux / Debian

To interrogate evidence photos offline using Ollama vision models:

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull lightweight vision model
ollama pull llama3.2-vision    # High accuracy (~4.0 GB)
ollama pull moondream          # Ultra fast (~1.8 GB)

# 3. Verify model detection
matazero model list

# 4. Interrogate evidence photos
matazero ask evidence.jpg "Are there any anatomical or lighting inconsistencies suggesting synthetic generation?"
```

---

## 📑 CLI Reference

<details>
<summary><b>Click to expand full command reference</b></summary>

```text
matazero <command> [options] [targets...]

Core Commands:
  doctor      System health & environment diagnostic (Python, sandbox, Ollama, storage)
  scan        Smart 1-command evidence auto-triage with live progress and HTML dossier
  analyze     Run 7 extraction tiers over evidence files (supports -r, --glob, --filter, -j)
  ask         Interrogate an evidence image using your local Ollama vision model (offline)
  diff        Forensic comparison between two images (structure, metadata, DQT, pixels)
  stego       Deep steganography, bitplane slicing (0-7), and Chi-Square PoV inspection
  timeline    Reconstruct multi-asset chronological timelines and estimate clock drift
  cluster     Group evidence files by camera fleet, DQT tables, GPS, or visual similarity
  motion      Detect and carve embedded MP4/HEVC video streams from motion photos
  export      Export forensic findings to SQLite database or STIX 2.1 Threat Intel bundles
  locate      Forensic geolocation, reverse geocoding, solar chronolocation, 3D maps
  geo         Manage offline geospatial datasets, 3D KD-Tree indexing, NDJSON ingestion
  probe       Dump container segment and chunk structure with exact byte offsets
  extract     Extract embedded thumbnails, previews, payloads, or -x -y coordinate crops
  corpus      Manage and inspect the reference encoder fingerprint corpus
  model       Manage and inspect local Ollama vision models
  scope       Create, validate, or display an HMAC-signed authorization scope
  audit       Verify or export the tamper-evident audit log
  clean       Losslessly remove metadata in self-audit mode
  completion  Generate shell completion scripts (bash, zsh, fish)
```

### Key Flags Cheat-Sheet

| Subcommand | Flag | Long Flag | Description |
| :--- | :---: | :--- | :--- |
| `analyze` | `-a` | `--self-audit` | Run in self-audit mode without external legal scope |
| `analyze` | `-s` | `--scope` | Path to HMAC-signed authorization scope JSON |
| `analyze` | | `--deep` | Display full hierarchical 7-tier forensic tree |
| `analyze` | | `--summary` | Display executive visual summary dashboard |
| `analyze` | `-e` | `--ela` | Enable Error Level Analysis (Tier 6) |
| `analyze` | `-c` | `--carve` | Automatically extract trailing payloads and archives |
| `analyze` | `-j` | `--jobs` | Number of parallel worker threads |
| `analyze` | `-f` | `--format` | Output format: `report`, `dashboard`, `deep`, `json`, `html` |
| `ask` | `-m` | `--model` | Local Ollama vision model (`llama3.2-vision`, `moondream`) |
| `locate` | `-f` | `--format` | Output: `table`, `json`, `geojson`, `html`, `kml`, `kmz` |
| `extract` | `-a` | `--all` | Extract all embedded artefacts, previews, and payloads |
| `extract` | `-c` | `--payload` | Extract trailing payload archives past EOI |

</details>

---

## 🧪 Testing & Quality Assurance

`matazero` maintains a rigorous automated test suite to ensure forensic precision, cross-platform file locking safety, and deterministic analytical outcomes.

```bash
# Run complete test suite with coverage
pytest

# Run specific subsystem test modules
pytest tests/test_cleaner.py      # Metadata stripping & zeroization tests
pytest tests/test_diff.py         # Forensic diff & comparison tests
pytest tests/test_reader.py       # Memory-mapped BoundedReader lifecycle tests
pytest tests/test_containers.py   # JPEG, PNG, TIFF container parsers
pytest tests/test_pipeline.py     # 7-tier forensic extraction pipeline
```

* **Deterministic Resource Management**: Every file reader wraps OS handles in strict `try ... finally` lifecycles to prevent Windows memory-mapped lock issues (`WinError 32`).
* **Silent Error Elimination**: All exception handlers utilize structured logging to maintain an airtight audit trail without dropping forensic anomalies.

---

## 🏛️ Architecture & Modular Engine

The CLI and core analytical pipeline follow a decoupled, modular design:

```
matazero/
├── imgint/
│   ├── cli/
│   │   ├── main.py               # Top-level CLI argument routing & parser
│   │   └── commands/             # Dedicated modular subcommands
│   │       ├── analyze.py        # 7-tier pipeline execution
│   │       ├── ask.py            # Local Ollama vision interrogation
│   │       ├── clean.py          # Lossless metadata cleaning
│   │       ├── diff.py           # Multi-tier image comparison
│   │       ├── doctor.py         # Diagnostic health checker
│   │       ├── extract.py        # Artefact & payload carving
│   │       ├── locate.py         # Chronolocation & reverse geocoding
│   │       ├── scan.py           # Bulk triage & HTML dossier generation
│   │       └── ...               # Additional specialized subcommands
│   └── core/
│       ├── analyzer/             # CFA, Copy-Move, Ghost, Hashes, Indicators
│       ├── artefact/             # IFD1, MPF, previews, payload carver
│       ├── container/            # Format parsers (JPEG, PNG, GIF, BMFF, TIFF)
│       ├── evidence/             # Cryptographic custody & evidence store
│       ├── fingerprint/          # DQT, DHT, ISP hardware corpus matching
│       ├── geo/                  # Offline geocoding & solar chronolocation
│       └── sandbox/              # Subprocess isolation for decoding tasks
└── tests/                        # Full regression & unit test suite
```

---

## 🛡️ Guarantees & Forensic Standards

`matazero` is built for court admissibility and strict adherence to forensic integrity:

* 🔒 **Air-Gapped Operation**: 100% offline. Zero telemetry, zero web beacons, zero remote database queries.
* 🛡️ **Cryptographic Custody**: SHA-256 digest calculated at ingest; append-only hash-chained audit logs detect any post-ingest file tampering.
* ⚖️ **Deterministic Confidence**: Every finding explicitly states its tier, extractor, confidence ranking, and legal caveat.
* 🚫 **Ethical Safeguards**: Zero biometric surveillance or facial recognition scraping. Built solely for defensive forensic verification.

---

## 📚 Documentation & Technical Plans

* [Architecture & Decision Records](plan/ARCHITECTURE.md)
* [Software Requirements Document (SRD)](plan/SRD.md)
* [Product Requirements Document (PRD)](plan/PRD.md)
* [Security Policy & Threat Model](docs/SECURITY.md)
* [Ethics & Governance Standards](docs/ETHICS.md)

---

## 📄 License

Distributed under the **Apache 2.0 License**. See [LICENSE](LICENSE) for full terms.
