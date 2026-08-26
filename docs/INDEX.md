# matazero Documentation Index & Architecture Map

Welcome to the **matazero** documentation. This index organizes the architectural specifications, requirements, security policies, and user manuals in sequential order.

---

## 1. Specifications & Engineering Blueprints (`plan/`)

The core architecture of matazero is built according to 5 formal engineering specifications:

| Order | Document | Title | Description |
|:---:|:---|:---|:---|
| **01** | [PRD.md](../plan/PRD.md) | **Product Requirements Document** | Problem statement, 7 extraction tiers, analytical/governance gaps, goals, and non-goals. |
| **02** | [SRD.md](../plan/SRD.md) | **Software Requirements Document** | Functional requirements (FR-1 to FR-12), governance rules (GR-1 to GR-4), and non-functional bounds (NFR-1 to NFR-4). |
| **03** | [SRS.md](../plan/SRS.md) | **Software Requirements Specification** | Detailed technical contracts, data models, error codes (0-7), schema definitions, and CLI grammar. |
| **04** | [ARCHITECTURE.md](../plan/ARCHITECTURE.md) | **Architecture & Decision Records** | Subsystem layouts, layered data flow, bounds safety caps, and Architectural Decision Records (ADR-001 to ADR-008). |
| **05** | [PLAN.md](../plan/PLAN.md) | **Implementation & Verification Plan** | Multi-phase development roadmap, milestone tracking, and verification checklists. |

---

## 2. Policy & Threat Governance (`docs/`)

| Document | Title | Description |
|:---|:---|:---|
| [SECURITY.md](SECURITY.md) | **Security Policy & Threat Model** | Memory limits, parser isolation sandbox (ADR-004), XXE prevention, decompresion bomb caps, and vulnerability reporting. |
| [ETHICS.md](ETHICS.md) | **Ethics & Human Rights Governance** | Binding code-enforced refusals against biometric recognition, mass scraping, cross-platform tracking, and false certainty. |

---

## 3. Directory Layout

```
mata/
├── .gitignore                   # Git exclusion rules
├── LICENSE                      # Apache 2.0 License
├── README.md                    # Primary repository overview, quickstart & short flags table
├── pyproject.toml / setup.py    # Python build and packaging metadata
├── matazero.py / mata.py        # Root direct convenience runners
├── matazero/ & mata/            # Module package entry points
├── imgint/                      # Core forensics & intelligence engine
│   ├── cli/main.py              # Unified CLI interface (scope, analyze, probe, corpus, audit, clean, completion)
│   ├── core/                    # Engine implementation
│   │   ├── analyzer/            # Tiers 4-7 analysers (Hashing, GeoTime & Solar Chronolocation, Indicators)
│   │   ├── artefact/            # Embedded thumbnails, MPF frames, Trailing archive carver
│   │   ├── clean/               # Lossless metadata stripper for self-audit mode
│   │   ├── container/           # Readers for JPEG, PNG, TIFF/RAW, GIF, WebP, ISO-BMFF (HEIC/AVIF)
│   │   ├── data/                # Reference encoder corpus (22+ profiles) and offline GeoNames dataset
│   │   ├── evidence/            # Immutable evidence store and cryptographic custody verifier
│   │   ├── fingerprint/         # DQT tables, Huffman DHT, Chroma subsampling, Corpus learning engine
│   │   ├── governance/          # HMAC Authorization scopes, Hash-chained audit logs, Capability refusals
│   │   ├── model/               # Data classes: Finding, Confidence, Provenance, AnalysisRecord, StructuralUnit
│   │   ├── report/              # Renderers: Text report, JSON, NDJSON, Summary table, Standalone HTML dossier
│   │   ├── sandbox/             # Subprocess worker isolation for untrusted pixel decode operations
│   │   ├── sniff/               # Magic-byte format sniffer & extension mismatch detector
│   │   ├── source/              # BoundedReader memory safety caps
│   │   └── standard/            # Parsers for EXIF 2.32, safe entity-disabled XMP, IPTC 8BIM, ICC, C2PA manifests
├── samples/                     # Test data & example authorization scopes
│   ├── evidence_sample.jpg      # Sample evidence image
│   ├── sample_scope.json        # Example signed scope file
│   └── README.md                # Sample usage instructions
├── plan/                        # Engineering blueprints (PRD, SRD, SRS, ARCHITECTURE, PLAN)
├── docs/                        # Security & ethics policies
└── tests/                       # Complete 25-test verification suite
```
