# Software Requirements Document — imgint

**Version:** 2.0 (draft)
**Status:** Proposed
**Last updated:** 2026-08-25
**Relationship to SRS:** this document is the requirement *catalogue* — what must be true, numbered and traceable to tests. `SRS.md` is the formal *specification* — interfaces, stimulus/response behaviour, and the data dictionary.

---

## 1. Introduction

### 1.1 Purpose
Defines functional and non-functional requirements for imgint v1, each numbered, testable, and traceable.

### 1.2 Scope
A command-line application and library that extracts, analyses, and reports on signals recoverable from image files, under enforced authorization and chain-of-custody controls.

### 1.3 Definitions

| Term | Meaning |
|---|---|
| **Authorization scope** | A signed file bounding what may be examined, for what purpose, under what legal basis, until when |
| **Evidence store** | Read-only originals plus separate working copies, with hashes recorded at ingest |
| **Audit log** | Append-only, hash-chained record of every action taken |
| **Signal tier** | Extraction category 1–7 as defined in `PLAN.md` §1 |
| **Encoder fingerprint** | Composite of quantization tables, Huffman tables, subsampling, and segment ordering |
| **Finding** | A single output assertion carrying value, provenance, confidence, and caveat |
| **Confidence** | One of `observed`, `derived`, `indicative`, `inconclusive` |
| **Sandbox** | Isolated subprocess with no network, no credentials, scratch-only filesystem, and resource caps |

### 1.4 Conventions
**MUST** = mandatory for v1. **SHOULD** = strongly expected. **MAY** = optional. **MUST NOT** = prohibited, verified by test.

---

## 2. Governance requirements *(P0 — implemented first)*

### 2.1 Authorization

| ID | Requirement |
|---|---|
| GR-1.1 | The system MUST refuse all extraction operations unless a valid authorization scope is loaded |
| GR-1.2 | The scope MUST record: case identifier, purpose, legal basis, authorising party, data-subject categories, permitted operations, retention period, and expiry date |
| GR-1.3 | The system MUST refuse to operate on an expired scope, with no override flag |
| GR-1.4 | The system MUST verify the scope's integrity (signature or hash) before use |
| GR-1.5 | The scope MUST be able to disable individual analysers; disabled analysers MUST NOT execute |
| GR-1.6 | The active scope identifier and hash MUST appear in every report |
| GR-1.7 | A `--self-audit` mode MAY operate without a scope, restricted to files owned by the invoking user and producing no case record |

### 2.2 Chain of custody

| ID | Requirement |
|---|---|
| GR-2.1 | SHA-256 of each input MUST be computed and logged before any other processing |
| GR-2.2 | Original files MUST be opened read-only; all operations MUST use working copies |
| GR-2.3 | Original hashes MUST be re-verified at end of run; any mismatch MUST be reported as a critical error |
| GR-2.4 | The audit log MUST be append-only and hash-chained, each entry containing the previous entry's hash |
| GR-2.5 | Every file access, analyser execution, network call, and report generation MUST produce an audit entry |
| GR-2.6 | Audit entries MUST record: timestamp (UTC), operator, scope ID, action, target hash, outcome |
| GR-2.7 | The system MUST provide `audit verify` to check chain integrity and report the first broken link |
| GR-2.8 | Reports MUST record tool version, corpus version, scope ID, and analysis timestamp |

### 2.3 Refused capabilities

| ID | Requirement |
|---|---|
| GR-3.1 | The system MUST NOT implement face detection, recognition, or biometric matching |
| GR-3.2 | The system MUST NOT scrape, crawl, or bulk-collect from online platforms |
| GR-3.3 | The system MUST NOT perform automated cross-platform identity correlation of individuals |
| GR-3.4 | The system MUST NOT provide continuous or real-time location tracking |
| GR-3.5 | The system MUST NOT query external hash databases |
| GR-3.6 | The system MUST NOT emit boolean verdicts on authenticity or manipulation |
| GR-3.7 | Refusals GR-3.1 to GR-3.6 MUST NOT be reachable via any flag, config, or environment variable |
| GR-3.8 | `ETHICS.md` MUST document every refusal and its rationale |

### 2.4 Operational security

| ID | Requirement |
|---|---|
| GR-4.1 | The system MUST make no network connection unless explicitly enabled per invocation |
| GR-4.2 | The system MUST NOT emit telemetry, update checks, or crash reports |
| GR-4.3 | Every network call MUST be logged and MUST appear in the report as a disclosure event |
| GR-4.4 | Reverse geocoding MUST default to a bundled offline dataset |
| GR-4.5 | The system MUST be fully functional on an air-gapped host |
| GR-4.6 | GPS coordinates MUST NOT appear in logs at default or verbose levels |

---

## 3. Functional requirements

### 3.1 Acquisition and detection

| ID | Requirement |
|---|---|
| FR-1.1 | Format MUST be identified by magic bytes, never by extension |
| FR-1.2 | Extension/format mismatch MUST be reported as a finding, not merely a warning — it is a signal |
| FR-1.3 | The system MUST detect JPEG, TIFF (both endiannesses), PNG, WebP, HEIC, HEIF, AVIF |
| FR-1.4 | The system SHOULD detect GIF, PSD, BMP, SVG |
| FR-1.5 | Unsupported formats MUST exit 3 naming the first 8 bytes in hex |
| FR-1.6 | Recursive directory ingest MUST be supported with include/exclude filters |

### 3.2 Tier 1 — metadata

| ID | Requirement |
|---|---|
| FR-2.1 | MUST parse EXIF/TIFF IFDs, both endiannesses, value types 1–12 |
| FR-2.2 | MUST recurse into Exif sub-IFD `0x8769`, GPS IFD `0x8825`, Interop IFD `0xA005`, and IFD1 |
| FR-2.3 | MUST preserve RATIONAL and SRATIONAL as integer pairs internally |
| FR-2.4 | MUST parse XMP as RDF/XML with external entity resolution disabled |
| FR-2.5 | MUST reassemble Extended XMP across multiple JPEG APP1 segments |
| FR-2.6 | MUST parse IPTC-IIM from 8BIM resource blocks |
| FR-2.7 | MUST reassemble multi-chunk ICC profiles and report the count of distinct profiles present |
| FR-2.8 | MUST parse PNG `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, `pHYs` |
| FR-2.9 | MUST decode text per each standard's own encoding rules and normalise output to UTF-8 |
| FR-2.10 | MUST preserve MakerNote as an opaque blob with offset and length; MUST NOT interpret it |
| FR-2.11 | SHOULD parse C2PA/JUMBF manifests, reporting presence, claim generator, and validation status |

### 3.3 Tier 2 — encoder fingerprints

| ID | Requirement |
|---|---|
| FR-3.1 | MUST extract all JPEG quantization tables from `DQT` with table identifiers |
| FR-3.2 | MUST extract Huffman tables from `DHT` and classify as default or optimised |
| FR-3.3 | MUST extract chroma subsampling from `SOF` component sampling factors |
| FR-3.4 | MUST record segment/chunk order as an ordered type sequence |
| FR-3.5 | MUST record restart interval from `DRI` when present |
| FR-3.6 | MUST compute a stable composite fingerprint hash from FR-3.1 to FR-3.5 |
| FR-3.7 | MUST match the fingerprint against a versioned reference corpus and report matches with similarity scores |
| FR-3.8 | MUST report `insufficient reference data` rather than a low-confidence guess when no match exceeds threshold |
| FR-3.9 | MUST report the corpus version used for any attribution |
| FR-3.10 | SHOULD detect double-compression indicators from DCT coefficient histograms |
| FR-3.11 | SHOULD fingerprint PNG filter and compression strategy |

### 3.4 Tier 3 — embedded artefacts

| ID | Requirement |
|---|---|
| FR-4.1 | MUST extract the EXIF IFD1 thumbnail when present |
| FR-4.2 | MUST compare thumbnail against a downscaled main image and report divergence with a similarity score |
| FR-4.3 | MUST report thumbnail dimensions and aspect ratio, flagging aspect mismatch as a crop indicator |
| FR-4.4 | MUST extract MPF images from JPEG APP2 `MPF\0` |
| FR-4.5 | MUST detect and extract trailing data after `FFD9` (JPEG) or `IEND` (PNG), reporting size and detected type |
| FR-4.6 | MUST extract embedded JPEG previews from TIFF-based RAW formats |
| FR-4.7 | MUST report container anomalies: illegal ordering, unexpected chunks, duplicate segments |
| FR-4.8 | MUST make all extracted artefacts individually exportable |

### 3.5 Tier 4 — hashing

| ID | Requirement |
|---|---|
| FR-5.1 | MUST compute SHA-256 of the whole file at ingest, before other processing |
| FR-5.2 | MUST compute SHA-256 of the image data stream alone, excluding metadata |
| FR-5.3 | SHOULD compute aHash, dHash, and pHash for corpus-internal correlation |
| FR-5.4 | Perceptual hashes MUST be labelled as corpus-internal only and MUST NOT be sent anywhere |
| FR-5.5 | SHOULD cluster near-duplicates within a batch by perceptual distance, with a configurable threshold |

### 3.6 Tier 5 — geospatial and temporal

| ID | Requirement |
|---|---|
| FR-6.1 | MUST convert GPS rational triplets and hemisphere refs to signed decimal degrees |
| FR-6.2 | MUST report altitude, DOP, and GPS timestamp when present |
| FR-6.3 | MUST reverse-geocode using a bundled offline dataset by default |
| FR-6.4 | MUST compute solar azimuth and elevation from GPS and timestamp, presented as expected values for analyst comparison |
| FR-6.5 | MUST cross-check `DateTimeOriginal` against `GPSDateStamp` and report divergence |
| FR-6.6 | MUST cross-check timezone offset plausibility against longitude |
| FR-6.7 | MUST report when filesystem mtime precedes claimed capture time |
| FR-6.8 | All temporal outputs MUST be labelled as claims, not established facts |

### 3.7 Tier 6 — indicators

| ID | Requirement |
|---|---|
| FR-7.1 | Every Tier-6 output MUST be a named indicator with a confidence value, never a verdict |
| FR-7.2 | Every indicator MUST carry caveat text naming its common false-positive causes |
| FR-7.3 | Every indicator MUST have a measured false-positive rate published in documentation |
| FR-7.4 | MUST report metadata timeline contradictions |
| FR-7.5 | MUST report quantization inconsistency where measurable |
| FR-7.6 | MUST report C2PA manifests that are present but fail validation |
| FR-7.7 | ELA, if implemented, MUST be behind an explicit flag, MUST carry a mandatory caveat, and MUST NOT appear in default output |
| FR-7.8 | The system MUST NOT aggregate indicators into a single authenticity score |
| FR-7.9 | Absence of metadata MUST be reported as `metadata absent — normal for platform-distributed images`, never as an anomaly |

### 3.8 Tier 7 — content-derived

| ID | Requirement |
|---|---|
| FR-8.1 | Pixel-level analysis MUST execute only inside the sandbox |
| FR-8.2 | OCR, if implemented, MUST be opt-in and sandboxed |
| FR-8.3 | LSB entropy screening, if implemented, MUST be labelled an indicator with a published false-positive rate |
| FR-8.4 | MUST report dominant colours, aspect ratio, and entropy summary |

### 3.9 Reporting

| ID | Requirement |
|---|---|
| FR-9.1 | Output formats MUST include `json`, `ndjson`, and human-readable `report` |
| FR-9.2 | Every finding MUST carry: value, source tier, extractor, byte offset where applicable, confidence, and caveat |
| FR-9.3 | Output MUST carry a schema version identifier |
| FR-9.4 | Structured output MUST go to stdout; all diagnostics and progress to stderr |
| FR-9.5 | Reports MUST be exportable with a hash manifest covering every referenced artefact |
| FR-9.6 | Reports SHOULD be signable |
| FR-9.7 | Human-readable reports MUST lead with a "what this does not establish" section |
| FR-9.8 | Absent data MUST be omitted, never rendered as null or empty |

### 3.10 CLI

| ID | Requirement |
|---|---|
| FR-10.1 | Subcommands MUST include: `scope`, `ingest`, `analyze`, `probe`, `report`, `audit`, `clean`, `completion` |
| FR-10.2 | `--help` MUST be available at root and subcommand level; `--version` MUST be supported |
| FR-10.3 | `--tiers` MUST select which extraction tiers run |
| FR-10.4 | `--jobs N` MUST parallelise while preserving deterministic output order |
| FR-10.5 | Colour MUST be emitted only to a TTY, honouring `NO_COLOR` and `--no-color` |
| FR-10.6 | SIGINT MUST stop cleanly, flush the audit log, and remove temporary files |
| FR-10.7 | Completions MUST be generated for bash, zsh, and fish |
| FR-10.8 | Configuration precedence MUST be flags > environment > config file > defaults, documented in `--help` |
| FR-10.9 | Destructive operations MUST be dry-run by default, requiring `--commit` |

### 3.11 Exit codes

| ID | Code | Meaning |
|---|---|---|
| FR-11.1 | 0 | Complete success |
| FR-11.2 | 1 | Runtime error |
| FR-11.3 | 2 | Usage error |
| FR-11.4 | 3 | Unsupported format or no signals found |
| FR-11.5 | 4 | Partial success |
| FR-11.6 | 5 | Resource budget exceeded |
| FR-11.7 | 6 | Authorization failure — no scope, expired, or operation outside scope |
| FR-11.8 | 7 | Chain-of-custody failure — original hash mismatch or broken audit chain |

---

## 4. Non-functional requirements

### 4.1 Security

| ID | Requirement | Verification |
|---|---|---|
| NFR-1.1 | Pixel decoding MUST occur only in an isolated subprocess with no network, no credentials, and scratch-only filesystem access | Sandbox test |
| NFR-1.2 | The sandbox MUST enforce memory, CPU-time, and wall-clock caps | Resource test |
| NFR-1.3 | Parent MUST survive any child crash, hang, or OOM and continue the batch with a diagnostic | Fault injection |
| NFR-1.4 | Every read MUST be bounds-checked against actual file length | Code review + fuzz |
| NFR-1.5 | Allocation MUST NOT be sized by an untrusted field without validating against remaining bytes | Code review + fuzz |
| NFR-1.6 | Recursion depth (default 16) and unit count per file (default 4096) MUST be capped | Crafted-input test |
| NFR-1.7 | XML parsing MUST disable external entities and cap expansion | XXE and billion-laughs tests |
| NFR-1.8 | Decompression MUST enforce an output cap (default 16MB) | Zip-bomb test |
| NFR-1.9 | 24 hours of fuzzing MUST produce zero crashes, hangs, or unbounded allocations | CI fuzz job |
| NFR-1.10 | Metadata-derived path components MUST be sanitised; writes outside the destination root MUST be refused | Traversal test |
| NFR-1.11 | `SECURITY.md` and `ETHICS.md` MUST document threat model, refusals, and reporting process | Doc review |

### 4.2 Analytical integrity

| ID | Requirement | Verification |
|---|---|---|
| NFR-2.1 | No output MUST assert authenticity or manipulation as fact | Schema validation in CI |
| NFR-2.2 | Every derived finding MUST carry confidence and caveat; schema validation MUST fail otherwise | CI schema test |
| NFR-2.3 | Every indicator MUST have a false-positive rate measured on the labelled corpus and published | Corpus study |
| NFR-2.4 | Attribution MUST degrade to `insufficient reference data` rather than guessing | Threshold test |
| NFR-2.5 | Identical input, version, and corpus version MUST produce byte-identical output | Determinism test, 100 runs |
| NFR-2.6 | Corpus version MUST be recorded in every report | Report inspection |

### 4.3 Performance

| ID | Requirement | Verification |
|---|---|---|
| NFR-3.1 | `--version` MUST return in under 50ms | Benchmark p95 |
| NFR-3.2 | Tier 1–3 analysis MUST reach ≥100 images/sec with `--jobs 8` | Benchmark |
| NFR-3.3 | Full-tier analysis MUST reach ≥10 images/sec with `--jobs 8` | Benchmark |
| NFR-3.4 | Memory MUST stay below 256MB per worker including sandbox overhead | Benchmark on 80MB RAW |
| NFR-3.5 | Tier 1–3 MUST NOT read more than 1MB or 5% of file size, whichever is greater | Instrumented counter |

### 4.4 Reliability

| ID | Requirement | Verification |
|---|---|---|
| NFR-4.1 | Malformed or truncated input MUST yield partial results with diagnostics, not a crash | Corpus test |
| NFR-4.2 | One file's failure MUST NOT abort a batch | Batch test |
| NFR-4.3 | The audit log MUST survive abnormal termination without chain corruption | Kill test |
| NFR-4.4 | Concurrency MUST NOT alter output content or ordering | `--jobs 1` vs `--jobs 16` diff |

### 4.5 Compatibility and maintainability

| ID | Requirement | Verification |
|---|---|---|
| NFR-5.1 | MUST run on Linux, macOS, and Windows, x86-64 and ARM64 | CI matrix |
| NFR-5.2 | MUST ship as a self-contained executable plus a bundled offline dataset | Clean-container test |
| NFR-5.3 | Adding a container format MUST require one interface implementation, no changes elsewhere | Architecture review |
| NFR-5.4 | Adding an analyser MUST require one interface implementation and a registry entry | Architecture review |
| NFR-5.5 | The library MUST be usable without the CLI; `pkg/` MUST NOT touch standard streams or exit | Import lint |
| NFR-5.6 | Container and analyser layer coverage MUST exceed 80% | Coverage report |
| NFR-5.7 | The labelled corpus MUST contain ≥150 images with ground truth across formats, platforms, and edit states | Corpus inventory |

---

## 5. Constraints and assumptions

**Constraints**
- Single developer; scope bounded by the phase plan in `PLAN.md`
- Offline operation mandatory; network optional and always disclosed
- Sandboxing mechanisms differ per platform and must be abstracted
- Legal requirements vary by jurisdiction; the tool provides mechanism, not legal advice

**Assumptions**
- Files are already lawfully in the operator's possession; the tool does not acquire them
- Operators for the DFIR and journalism personas have relevant domain training
- The labelled corpus can be assembled from self-captured and freely licensed material with recorded ground truth

---

## 6. Verification approach

| Method | Applied to |
|---|---|
| Unit tests | Container readers, block parsers, individual analysers |
| Golden-file snapshots | Canonical output over the committed corpus |
| Differential tests | Tier 1 against ExifTool; divergences documented |
| Ground-truth study | Attribution accuracy and per-indicator false-positive rates |
| Property tests | Originals unmodified; audit chain intact; `clean` preserves image bytes exactly |
| Fuzzing | Container layer and sandbox boundary, continuous in CI |
| Fault injection | Child crash, hang, OOM, and abnormal parent termination |
| Network monitoring | Zero egress by default (GR-4.1, GR-4.2) |
| Schema validation | No finding without confidence and caveat (NFR-2.2) |
| Comprehension study | Five readers correctly state what a report does and does not establish |

---

## 7. Traceability

| Group | Design reference | Test suite |
|---|---|---|
| GR-1.x authorization | ARCHITECTURE §3 Governance, ADR-001 | `test_scope_*` |
| GR-2.x custody | ARCHITECTURE §3 Evidence Store, ADR-002 | `test_custody_*` |
| GR-3.x refusals | ARCHITECTURE ADR-003 | `test_refusal_*` |
| GR-4.x opsec | ARCHITECTURE ADR-005 | `test_offline_*` |
| FR-1.x–FR-2.x | ARCHITECTURE §3 Container/Standard layers, ADR-006 | `test_container_*`, `test_parse_*` |
| FR-3.x fingerprints | ARCHITECTURE §3 Fingerprint Engine, ADR-007 | `test_fingerprint_*` |
| FR-4.x–FR-5.x | ARCHITECTURE §3 Artefact Extractors | `test_artefact_*` |
| FR-6.x–FR-8.x | ARCHITECTURE §3 Analyser Registry, ADR-004 | `test_analyse_*` |
| FR-9.x reporting | ARCHITECTURE §3 Reporter, ADR-008 | `test_report_*` |
| NFR-1.x security | ARCHITECTURE ADR-004 | `fuzz_*`, `test_sandbox_*` |
| NFR-2.x integrity | ARCHITECTURE ADR-008 | `test_confidence_*`, corpus study |
