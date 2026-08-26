# Software Requirements Specification — imgint

**Version:** 2.0 (draft)
**Status:** Proposed
**Date:** 2026-08-25
**Structure:** IEEE 830-style
**Relationship to SRD:** `SRD.md` is the numbered requirement catalogue. This document is the formal specification — product perspective, external interfaces, stimulus/response behaviour, and the data dictionary. Requirement IDs referenced here (GR-, FR-, NFR-) are defined in `SRD.md`.

---

## 1. Introduction

### 1.1 Purpose
Specifies the behaviour, interfaces, and data structures of imgint v1 in sufficient detail for implementation and acceptance testing.

### 1.2 Intended audience
The implementer; reviewers assessing design adequacy; test authors deriving acceptance cases; analysts evaluating whether the tool is appropriate for their workflow.

### 1.3 Product scope
imgint extracts and analyses signals recoverable from image files under enforced authorization and chain-of-custody controls, producing evidence-grade reports with per-finding provenance and confidence.

It does not acquire files, identify people, or reach conclusions on the operator's behalf.

### 1.4 References
- EXIF 2.32 (CIPA DC-008)
- ITU-T T.81 / ISO-IEC 10918-1 (JPEG)
- ISO 15948 (PNG), ISO 14496-12 (ISO-BMFF), ISO 32000 / ICC.1 (ICC profiles)
- XMP Specification Part 1 (ISO 16684-1)
- IPTC Information Interchange Model 4.2
- C2PA Specification 2.x
- NOAA Solar Position Algorithm
- Project documents: `PRD.md`, `SRD.md`, `PLAN.md`, `ARCHITECTURE.md`

---

## 2. Overall description

### 2.1 Product perspective
A self-contained desktop command-line application with an embeddable library core. No server component, no account, no network dependency. It sits between file acquisition (out of scope) and analyst judgement (out of scope), and produces structured evidence for the latter.

```
Lawfully acquired files ──▶ [ imgint ] ──▶ Findings + report + audit trail ──▶ Analyst judgement
                                 ▲
                      Authorization scope
```

### 2.2 Product functions
| F | Function |
|---|---|
| F-1 | Load and enforce an authorization scope |
| F-2 | Ingest files into an evidence store with hashing and read-only originals |
| F-3 | Detect container format and enumerate structure |
| F-4 | Extract metadata across six standards |
| F-5 | Extract encoder fingerprints and attempt attribution |
| F-6 | Extract embedded artefacts and trailing data |
| F-7 | Compute cryptographic and perceptual hashes |
| F-8 | Perform geospatial and temporal consistency analysis |
| F-9 | Produce indicators with confidence and caveats |
| F-10 | Generate structured and human-readable reports with hash manifests |
| F-11 | Maintain and verify a hash-chained audit log |
| F-12 | Remove sensitive metadata without altering image data |

### 2.3 User classes

| Class | Frequency | Expertise | Privilege |
|---|---|---|---|
| Verification journalist | Daily | Domain-high, forensics-low | Standard scope |
| DFIR analyst | Daily | Forensics-high | Full scope + custody export |
| Security researcher | Occasional | Technical-high | Standard scope |
| Privacy self-auditor | Rare | Low | `--self-audit` only, own files, no case record |
| Student | Frequent | Learning | Training scope on the demo corpus |

### 2.4 Operating environment
Linux (kernel 5.10+), macOS 12+, Windows 10+; x86-64 and ARM64. No runtime dependency beyond the binary and its bundled offline dataset. Sandboxing uses seccomp-bpf on Linux, `sandbox_init` on macOS, and Job Objects with a restricted token on Windows.

### 2.5 Design and implementation constraints
- Offline by default; every network call disclosed (GR-4.1, GR-4.3)
- Pixel decoding only inside the sandbox (NFR-1.1)
- No feature may emit an authenticity verdict (GR-3.6, NFR-2.1)
- Refused capabilities not reachable by configuration (GR-3.7)
- Library core must not touch standard streams or exit (NFR-5.5)

### 2.6 Assumptions and dependencies
Files are already lawfully possessed. Authorization scopes are issued by a competent authority; imgint validates integrity and expiry, not legal sufficiency. Attribution accuracy depends on the bundled reference corpus and degrades as new devices appear.

---

## 3. External interface requirements

### 3.1 Command-line interface

```
imgint <command> [flags] [targets...]

  scope       Create, validate, or display an authorization scope
  ingest      Hash and register files into the evidence store
  analyze     Run extraction tiers over ingested files
  probe       Dump container structure with offsets and lengths
  report      Generate a report from analysis results
  audit       Verify or export the audit log
  clean       Remove sensitive metadata (self-audit mode)
  completion  Emit a shell completion script
```

**Global flags**

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--scope PATH` | path | env `IMGINT_SCOPE` | Authorization scope file |
| `--case ID` | string | from scope | Case identifier |
| `--tiers LIST` | list | `1,2,3,4` | Extraction tiers to run |
| `--format FMT` | enum | `report` on TTY, `json` otherwise | `json` \| `ndjson` \| `report` \| `table` |
| `--jobs N` | int | CPU count | Worker count; output order stays deterministic |
| `--allow-network` | bool | false | Enables disclosed, logged external lookups |
| `--no-color` | bool | false | Also honours `NO_COLOR` |
| `--commit` | bool | false | Required for any destructive operation |
| `--self-audit` | bool | false | Scope-free mode, own files only, no case record |
| `--verbose` | bool | false | Diagnostics to stderr; never GPS (GR-4.6) |

**Environment variables:** `IMGINT_SCOPE`, `IMGINT_STORE`, `IMGINT_CORPUS`, `NO_COLOR`.
**Precedence:** flags > environment > config file > defaults (FR-10.8).

### 3.2 Programmatic interface

```
Analyzer
    ID() string
    Tier() int
    RequiresDecode() bool          // true ⇒ executes only in sandbox
    Analyze(ctx AnalysisContext) ([]Finding, []Diagnostic)

ContainerReader
    Sniff(head []byte) bool
    Walk(src Source, sink BlockSink) error

BlockParser
    Handles(kind BlockKind) bool
    Parse(bytes []byte, ctx BlockContext) ([]Field, []Diagnostic)
```

Contract: `Analyze` must not perform I/O outside `ctx`, must not access the network, and must return diagnostics rather than logging them.

### 3.3 File interfaces

| Artefact | Format | Notes |
|---|---|---|
| Authorization scope | Signed JSON | Schema in §5.1 |
| Evidence store | Directory | `originals/` read-only, `working/`, `manifest.json` |
| Audit log | Append-only JSONL | Hash-chained, schema in §5.3 |
| Reference corpus | Versioned SQLite | Fingerprint → device/software mappings |
| Geocoding dataset | Bundled binary index | Derived from GeoNames |
| Report | JSON + Markdown/PDF | Accompanied by a hash manifest |

### 3.4 Communication interfaces
None by default. With `--allow-network`, only explicitly listed lookup endpoints are permitted; each call is logged (GR-4.3) and surfaced in the report as a disclosure event. No telemetry, update check, or crash reporting under any configuration (GR-4.2).

---

## 4. System features

Each feature is given as stimulus → response.

### 4.1 Authorization enforcement
**Priority:** Critical · **Requirements:** GR-1.1 – GR-1.7

| Stimulus | Response |
|---|---|
| Any command run with no scope and no `--self-audit` | Exit 6; message naming the missing scope and how to create one |
| Scope loaded, integrity check fails | Exit 6; message identifying the failed check; audit entry recorded |
| Scope loaded, `expiry` in the past | Exit 6; message stating expiry date; **no override available** |
| Scope valid, requested operation not in `permitted_operations` | Exit 6; message naming the operation and the permitted set |
| Scope valid and operation permitted | Proceed; scope ID and hash recorded in audit log and report |
| `--self-audit` on a file not owned by the invoking user | Exit 6; message explaining the restriction |

### 4.2 Evidence ingest
**Priority:** Critical · **Requirements:** GR-2.1 – GR-2.3, FR-5.1

| Stimulus | Response |
|---|---|
| `ingest` on a file | SHA-256 computed first; original registered read-only; working copy created; audit entry written |
| Ingest of an already-registered identical hash | Deduplicated with a notice; no second copy created |
| Ingest of a different file with a colliding path | Both registered, distinguished by hash |
| Original's hash differs at end-of-run verification | Exit 7; critical error naming the file and both hashes |
| Write failure to the store | Exit 1; no partial registration left behind |

### 4.3 Structure and metadata extraction
**Priority:** High · **Requirements:** FR-1.x, FR-2.x

| Stimulus | Response |
|---|---|
| Supported format | Structure enumerated; metadata blocks located and parsed; findings emitted with byte offsets |
| Extension/format mismatch | Finding emitted (`container.extension_mismatch`, confidence `observed`) — treated as a signal, not a warning |
| Unknown format | Exit 3; first 8 bytes reported in hex |
| Malformed block mid-file | Diagnostic recorded; traversal continues; partial results returned |
| Cyclic IFD chain | Cycle detected via visited-offset set; diagnostic emitted; traversal terminates safely |
| Metadata entirely absent | Finding `metadata.absent` with caveat: normal for platform-distributed images (FR-7.9) |

### 4.4 Encoder fingerprinting
**Priority:** High · **Requirements:** FR-3.x

| Stimulus | Response |
|---|---|
| JPEG input | `DQT`, `DHT`, subsampling, segment order, `DRI` extracted; composite fingerprint computed |
| Fingerprint matches corpus above threshold | Attribution finding with similarity score, corpus version, confidence `derived` |
| No match above threshold | `insufficient reference data` — no guess emitted (FR-3.8) |
| Multiple matches above threshold | All returned, ranked, with an explicit ambiguity note |
| Double-compression signature detected | Indicator with confidence `indicative` and caveat covering platform re-encoding |
| Non-JPEG input | Format-appropriate fingerprint or explicit `not applicable` |

### 4.5 Artefact extraction
**Priority:** High · **Requirements:** FR-4.x

| Stimulus | Response |
|---|---|
| IFD1 thumbnail present | Extracted; compared with downscaled main; similarity score reported |
| Thumbnail aspect ratio differs from main | Crop indicator, confidence `indicative`, caveat on legitimate causes |
| Trailing data after EOI/IEND | Size, offset, and detected type reported; bytes exportable |
| MPF images present | Each extracted and individually addressable |
| Multiple ICC profiles | Count reported as a re-encode indicator |
| Container anomaly (ordering, duplicates) | Anomaly finding with the specific deviation named |

### 4.6 Sandboxed analysis
**Priority:** Critical · **Requirements:** NFR-1.1 – NFR-1.3, FR-8.1

| Stimulus | Response |
|---|---|
| Analyser with `RequiresDecode() == true` | Executed in sandboxed child; no network, no credentials, scratch-only filesystem |
| Child crashes | Parent records diagnostic, marks the file partially analysed, continues the batch |
| Child exceeds memory or time cap | Child terminated; diagnostic recorded; batch continues; exit 5 if any file affected |
| Child attempts a network call | Blocked by sandbox policy; security diagnostic recorded |
| Sandbox unavailable on the platform | Decode-requiring analysers refuse to run; explicit message; other tiers proceed |

### 4.7 Findings and reporting
**Priority:** Critical · **Requirements:** FR-9.x, NFR-2.1, NFR-2.2

| Stimulus | Response |
|---|---|
| Any derived finding produced | Emitted only with confidence and caveat populated; schema validation fails otherwise |
| `report` requested | Human-readable output leading with "what this does not establish" |
| Report exported | Hash manifest generated covering every referenced artefact |
| Multiple indicators present | Listed individually; **never aggregated into a score** (FR-7.8) |
| Attribution present | Corpus version recorded alongside it |
| Output piped | JSON to stdout only; all progress and diagnostics to stderr |

### 4.8 Audit trail
**Priority:** Critical · **Requirements:** GR-2.4 – GR-2.7

| Stimulus | Response |
|---|---|
| Any auditable action | Entry appended with timestamp, operator, scope ID, action, target hash, outcome, previous-entry hash |
| `audit verify` | Chain walked; `valid` or the index and hash of the first broken link reported |
| Abnormal termination | Log remains valid up to the last completed entry; no chain corruption |
| Network call made | Logged as a disclosure event and surfaced in the report |

### 4.9 Refused capabilities
**Priority:** Critical · **Requirements:** GR-3.1 – GR-3.8

| Stimulus | Response |
|---|---|
| Any request implying face recognition or biometric matching | Refused with a pointer to `ETHICS.md`; not reachable by any flag |
| Request for external hash-database lookup | Refused; rationale explained |
| Request for a single authenticity verdict or score | Refused; individual indicators returned instead |
| Attempt to enable a refused capability via config or environment | Ignored; refusal logged |

---

## 5. Data dictionary

### 5.1 Authorization scope

```json
{
  "schema": "imgint.scope/1",
  "case_id": "CASE-2026-0142",
  "purpose": "Verification of images submitted with story ref 8823",
  "legal_basis": "DPDP Act 2023 — legitimate use; editorial purpose",
  "authorized_by": {"name": "…", "role": "…", "org": "…"},
  "operator": "…",
  "data_subject_categories": ["unidentified persons in submitted imagery"],
  "permitted_operations": ["ingest", "analyze", "probe", "report"],
  "permitted_tiers": [1, 2, 3, 4, 5, 6],
  "network_allowed": false,
  "retention_days": 90,
  "issued": "2026-08-01T00:00:00Z",
  "expiry": "2026-11-01T00:00:00Z",
  "signature": "…"
}
```

### 5.2 Finding

```json
{
  "id": "fingerprint.processing_chain",
  "tier": 2,
  "extractor": "jpeg.dqt",
  "value": "Apple iPhone encoder → WhatsApp re-encode",
  "byte_offset": 604,
  "confidence": "derived",
  "similarity": 0.94,
  "corpus_version": "2026.08",
  "caveat": "Identifies encoding software, not a specific device or person. Similar tables appear across firmware versions.",
  "false_positive_rate": 0.07
}
```

**Confidence values**

| Value | Meaning |
|---|---|
| `observed` | Read directly from the file; no inference |
| `derived` | Computed from observed data by a deterministic rule |
| `indicative` | Suggests a possibility; requires analyst judgement; has a measured FP rate |
| `inconclusive` | Analysis ran but produced no usable signal |

There is deliberately no `confirmed`. Nothing this tool produces confirms anything on its own.

### 5.3 Audit entry

```json
{
  "seq": 1042,
  "timestamp": "2026-08-25T11:04:22.481Z",
  "operator": "saranya",
  "scope_id": "CASE-2026-0142",
  "action": "analyze",
  "target_sha256": "a3f1…",
  "analyzers": ["exif", "jpeg.dqt", "thumbnail.compare"],
  "outcome": "success",
  "diagnostics_count": 2,
  "prev_hash": "9c2e…",
  "entry_hash": "d71b…"
}
```

### 5.4 Analysis record (top level)

```json
{
  "schema": "imgint/1",
  "tool_version": "1.0.0",
  "corpus_version": "2026.08",
  "scope_id": "CASE-2026-0142",
  "analyzed_at": "2026-08-25T11:04:22Z",
  "file": {"path": "…", "size": 2847213, "sha256": "…", "imagedata_sha256": "…"},
  "container": {"format": "jpeg", "detected_by": "magic", "extension_matches": true},
  "findings": [ /* Finding objects */ ],
  "artefacts": [ {"kind": "thumbnail", "offset": 892, "size": 8214, "sha256": "…"} ],
  "diagnostics": [ {"level": "warning", "message": "icc: truncated at chunk 3 of 4"} ],
  "not_established": [
    "Who took this image",
    "Whether the depicted scene is authentic",
    "Whether the image was manipulated"
  ]
}
```

`not_established` is a required field. It appears in every record, and in the report it appears first.

---

## 6. Non-functional summary

Full requirements are in `SRD.md` §4. Headline targets:

| Attribute | Target |
|---|---|
| Startup | `--version` under 50ms |
| Throughput | ≥100 img/s tiers 1–3; ≥10 img/s full |
| Memory | <256MB per worker including sandbox |
| Robustness | 24h fuzzing, zero crashes or hangs |
| Containment | Zero sandbox escapes; parent survives all induced child failures |
| Egress | Zero unsolicited network connections |
| Determinism | Byte-identical output for identical input, version, and corpus version |
| Integrity | Every derived finding carries confidence and caveat, enforced by schema validation |

---

## 7. Acceptance criteria

v1 is accepted when all of the following hold:

1. All P0 requirements in `PRD.md` §6 are implemented and tested.
2. Tier 1 output agrees with ExifTool on ≥98% of corpus fields, with every divergence documented.
3. Attribution reaches ≥85% accuracy on the metadata-stripped labelled corpus.
4. Every Tier-6 indicator has a published, measured false-positive rate.
5. No output path can emit an authenticity verdict — verified by CI schema validation.
6. Zero sandbox escapes and zero parent failures across the fault-injection suite.
7. Zero network connections observed in a default run under network monitoring.
8. The audit chain verifies after normal completion, after SIGINT, and after `kill -9`.
9. Originals are byte-identical after every run in the corpus suite.
10. Five readers unfamiliar with the tool correctly state what a report does and does not establish.
11. `SECURITY.md` and `ETHICS.md` are published and complete.
12. Legal review of the authorization-scope model is complete for the intended jurisdiction.

---

## 8. Appendix — deferred and out of scope

| Item | Status | Note |
|---|---|---|
| Video and audio analysis | Deferred | Different container and codec model |
| ML-based manipulation detection | Deferred | Blocked until labelled corpus and measured error rates exist |
| Collaborative case management | Deferred | Multi-user custody is a distinct problem |
| Live acquisition | Out of scope | imgint analyses; it does not acquire |
| Face recognition, platform scraping, identity correlation, person tracking, external hash-DB lookup, authenticity verdicts | **Refused** | See `PRD.md` §3 and `ETHICS.md` |
