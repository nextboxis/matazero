# Product Requirements Document — imgint

**Product:** imgint — image intelligence toolkit for ethical OSINT and digital forensics
**Version:** 2.0 (draft)
**Status:** Proposed
**Owner:** Saranya
**Last updated:** 2026-08-25

---

## 1. Summary

imgint extracts every recoverable signal from an image file — metadata, encoder fingerprints, embedded artefacts, trailing data — and derives consistency checks and analytics from them, producing an evidence-grade report with per-finding provenance and confidence.

It is built for analysts who lawfully possess files and need to establish what those files are, where they came from, and whether their apparent history is internally consistent.

Governance is a product feature, not a policy document. The tool will not run without a loaded authorization scope, logs every action to a tamper-evident audit trail, and refuses a defined set of capabilities regardless of configuration.

---

## 2. Problem statement

Image verification currently requires stitching together five or six single-purpose tools, and the seams are where errors happen.

**Analytical gap.** Metadata extraction is well served. What is not served is the case where metadata has been removed — which is now the default, because every major platform strips it on upload. The structural signals that survive stripping (quantization tables, Huffman tables, subsampling, segment ordering) are legible but scattered across specialist tools and tribal knowledge.

**Interpretive gap.** Existing tools output raw signals and leave interpretation entirely to the user. This produces a well-documented failure pattern: absence of metadata read as evidence of tampering, ELA heat maps read as proof of manipulation, camera timestamps read as ground truth. Tools that emit findings without confidence ratings and false-positive context actively contribute to misidentification.

**Governance gap.** Almost no image-analysis tooling has chain of custody, authorization enforcement, or audit logging built in. Analysts working in legal, journalistic, or law-enforcement contexts bolt these on with spreadsheets and hope.

**Ethical gap.** The same extraction pipeline serves verification and surveillance. Tools that do not make the distinction structurally leave it entirely to the operator's conscience.

imgint addresses all four: recover what survives stripping, present it with honest uncertainty, wrap it in chain of custody, and enforce the boundaries in code.

---

## 3. Goals and non-goals

### Goals

| ID | Goal |
|---|---|
| G-1 | Extract all seven signal tiers from every Tier-1 image format through one command |
| G-2 | Attribute a processing chain from encoder fingerprints alone, when metadata is absent |
| G-3 | Present every derived finding with a confidence rating and false-positive context |
| G-4 | Maintain chain of custody sufficient to support an electronic-records certificate |
| G-5 | Operate fully offline, so no investigation leaks to a third party |
| G-6 | Enforce authorization scope, audit logging, and refused capabilities in code |
| G-7 | Process untrusted, potentially malicious images without compromising the host |

### Non-goals — binding, enforced in code

| ID | Refused capability | Rationale |
|---|---|---|
| NG-1 | Face recognition, face matching, or any biometric identification | Special-category data under GDPR Art. 9; the clearest boundary between forensics and surveillance |
| NG-2 | Scraping or bulk collection from online platforms | Outside the file-analysis remit; ToS and unauthorised-access exposure |
| NG-3 | Automated cross-platform identity correlation of private individuals | Deanonymisation-as-a-service under another name |
| NG-4 | Real-time or continuous location tracking of a person | Not investigation |
| NG-5 | Matching against external hash databases (PhotoDNA and equivalents) | Restricted-access programmes with their own governance; not appropriate in a general-purpose tool |
| NG-6 | Any workflow specifically targeting minors | No legitimate general-purpose version exists |
| NG-7 | Operation without a loaded, unexpired authorization scope | The control that gives the others force |
| NG-8 | Emitting a boolean verdict on authenticity or manipulation | Overclaim is the primary harm this category of tool causes |

### Deferred (not refused)
Video and audio analysis; live network acquisition; collaborative case management; ML-based manipulation detection (deferred until the labelled corpus and measured error rates exist to validate it).

---

## 4. Users

### Primary: verification journalist
Given an image circulating online, needs to establish plausibility fast, and needs to explain findings to an editor without a forensics background.
**Needs:** clear report, honest uncertainty, offline operation for source protection, findings expressed in plain language.
**Fails if:** the tool implies certainty it doesn't have, or leaks the investigation to an API provider.

### Primary: DFIR analyst
Working a case with legal consequences. Hundreds to thousands of images. Output may end up in court.
**Needs:** chain of custody, hash-chained audit log, deterministic and reproducible results, batch triage, signed reports.
**Fails if:** originals are modified, or a result cannot be reproduced six months later.

### Secondary: security researcher / blue team
Screening images for embedded payloads, polyglots, and steganographic carriers.
**Needs:** trailing-data detection, container anomaly reporting, sandboxed processing, measured false-positive rates.

### Secondary: privacy-conscious individual
Auditing what their own photos disclose before publishing.
**Needs:** plain-language sensitivity ranking, one-command removal, no network access, no expertise assumed.

### Secondary: student / educator
Learning image forensics with ground truth available.
**Needs:** labelled corpus, structure dumps that teach the formats, guided exercises.

---

## 5. User stories

| ID | As a… | I want to… | So that… |
|---|---|---|---|
| US-1 | journalist | learn what a metadata-stripped image still reveals | I can assess it when the obvious evidence is gone |
| US-2 | journalist | see confidence and caveats on every finding | I don't publish an overclaim |
| US-3 | journalist | run entirely offline | my investigation isn't disclosed to an API provider |
| US-4 | journalist | check whether GPS, timestamp, and sun position agree | I can test the claimed time and place |
| US-5 | DFIR analyst | have originals hashed and never modified | the evidence survives challenge |
| US-6 | DFIR analyst | produce a tamper-evident audit log | I can show exactly what was done and when |
| US-7 | DFIR analyst | triage 50,000 images by device and duplicate cluster | I spend my time on the ones that matter |
| US-8 | DFIR analyst | reproduce a result months later, exactly | my findings hold up |
| US-9 | researcher | detect appended data and container anomalies | I can screen for embedded payloads |
| US-10 | researcher | process hostile files safely | a malicious image can't compromise my workstation |
| US-11 | privacy user | see what my photo discloses, ranked by sensitivity | I know what I'm publishing |
| US-12 | privacy user | remove sensitive data without quality loss | the photo is still worth posting |
| US-13 | any user | be prevented from exceeding my authorization | the tool protects me as well as the subject |
| US-14 | student | inspect container structure with offsets | I learn the formats by reading real files |

---

## 6. Requirements by priority

### P0 — does not ship without these
- Governance frame: authorization scope, hash-chained audit log, read-only originals, working copies
- Tier 1 metadata across JPEG, PNG, WebP, HEIC/AVIF, TIFF
- Tier 2 encoder fingerprints for JPEG and PNG
- Tier 3 embedded thumbnail extraction and comparison; trailing-data detection
- Tier 4 cryptographic hashing on ingest
- Sandboxed decode as the default path
- Confidence rating and caveat text on every derived finding
- Fully offline operation; no network calls by default
- Versioned JSON schema; stdout/stderr separation; documented exit codes
- All NG-1 through NG-8 refusals enforced in code

### P1 — expected at launch
- MPF images, RAW previews, multiple-ICC detection
- Perceptual hashing and near-duplicate clustering
- Offline reverse geocoding; solar position; timeline consistency checks
- Tier 6 tampering indicators with measured false-positive rates
- Batch triage with device and duplicate clustering
- Signed report export with hash manifest
- Deletion-only privacy cleaning
- Shell completions; parallel processing with deterministic ordering

### P2 — post-launch
- C2PA manifest validation
- Sandboxed OCR
- LSB entropy screening
- SQLite case store
- WASM build with a browser tool that uploads nothing
- Expanded device fingerprint corpus, versioned and citable

---

## 7. Success metrics

| Metric | Target | Measured by |
|---|---|---|
| Attribution accuracy | ≥85% correct processing-chain identification on metadata-stripped corpus | Labelled corpus test |
| False-positive rate, Tier 6 | Measured and published for every indicator | Labelled corpus test |
| Overclaim incidents | Zero findings emitted without confidence and caveat | Output schema validation in CI |
| Chain of custody | 100% of runs produce a verifiable hash-chained log; zero originals modified | Integrity test |
| Reproducibility | Byte-identical output for identical input, version, and corpus version | Determinism test, 100 runs |
| Sandbox containment | Zero host escapes; parent survives 100% of induced child failures | Fault-injection test |
| Network egress | Zero unsolicited connections | Network monitor in CI |
| Throughput | ≥100 images/sec Tier 1–3; ≥10/sec with full analysis | Benchmark |
| Analyst comprehension | 5 of 5 test readers correctly state what a report does and does not establish | Manual study |

---

## 8. Competitive position

| Tool | Strength | Gap imgint addresses |
|---|---|---|
| **ExifTool** | Unmatched metadata coverage | Metadata only; no fingerprints, no governance, no confidence framing |
| **JPEGsnoop** | Excellent quantization-table analysis | Windows-only, unmaintained, JPEG-only, no batch or governance |
| **FotoForensics** | Accessible ELA and analysis | Hosted — uploading evidence to a third party is disqualifying for most real cases |
| **Autopsy / Sleuth Kit** | Strong DFIR governance | Filesystem-oriented; shallow image-specific analysis |
| **Ad-hoc scripts** | Flexible | No custody, no reproducibility, no shared corpus |

**Position:** the only tool combining survives-stripping structural analysis, honest uncertainty framing, chain of custody, and offline-by-default operation in one auditable pipeline.

**Stated limitation:** imgint will not match ExifTool's tag database and does not try to. It trades tag depth for structural analysis, governance, and analytical integrity.

---

## 9. Release plan

| Milestone | Contents | Exit criteria |
|---|---|---|
| **M0 — Governance** | Scope file, audit log, evidence store | Every later commit runs inside an existing governance frame |
| **M1 — Metadata** | Tier 1 across all Tier-1 formats | ≥98% agreement with ExifTool; divergences documented |
| **M2 — Fingerprints** | Tier 2 + seed reference corpus | ≥85% attribution on self-stripped images |
| **M3 — Artefacts** | Tier 3 + Tier 4 | Recovers cropped-out content from an embedded thumbnail |
| **M4 — Sandbox** | Isolated decode, pixel analytics | Malicious image kills child, parent continues cleanly |
| **M5 — Analysis** | Tiers 5–6 with measured error rates | Every indicator ships with a published false-positive rate |
| **M6 — Report** | Signed export, hash manifest | Report is usable as an exhibit without redrafting |
| **M7 — Ship** | Packaging, SECURITY.md, ETHICS.md, demo corpus | Stranger test passes |

---

## 10. Risks

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Findings overclaimed and someone is wrongly accused | Critical | Medium | No boolean verdicts (NG-8); mandatory confidence and caveat fields; measured FP rates; caveats in output, not just docs |
| Tool repurposed for surveillance or stalking | Critical | Medium | NG-1 through NG-7 enforced in code; authorization scope mandatory; audit log; published ETHICS.md |
| Sandbox escape via a decoder vulnerability | Critical | Low | Isolation by default; no credentials or network in child; resource caps; continuous fuzzing |
| Investigation leaked via an API lookup | High | Medium | Offline-first; network opt-in, per-call logged and surfaced in the report; no telemetry |
| Fingerprint corpus too thin for accuracy claims | High | High | Publish accuracy per corpus version; degrade to "insufficient reference data" rather than guessing |
| ELA misinterpreted as proof | High | High | Ship with an explicit caveat, an FP rate, and no verdict; consider omitting from default output |
| Evidence inadmissible on procedural grounds | High | Medium | Hash on ingest, read-only originals, hash-chained log, versioned reports; legal review before v1 |
| Scope drift into an ExifTool clone | Medium | Medium | Non-goals binding; every feature reviewed against them |

---

## 11. Open questions

1. **Should ELA ship at all?** It is expected by users and it is the most misused technique in the field. Options: omit entirely, or include behind a flag with a mandatory caveat and published FP rate. Currently leaning toward the latter.
2. **What legally constitutes a valid authorization scope?** Varies by jurisdiction and engagement type. Needs a legal review before v1, not after.
3. **How is the fingerprint corpus built and licensed?** Self-captured, crowd-sourced, or derived from public datasets — each has different provenance and licensing consequences for claims made from it.
4. **Does refusing NG-1 through NG-6 in code meaningfully help,** given the source is open and the checks are removable? Argument for: it establishes intent, protects good-faith users from accidental overreach, and makes any fork's removal of them a deliberate, documentable act.
5. **Retention defaults.** How long should the evidence store keep working copies before mandatory purge, and should expiry be enforced or advisory?
6. **Language.** Go for distribution and concurrency, Rust for sandboxing and hostile-input safety. See ADR-009.
