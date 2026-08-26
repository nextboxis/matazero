# imgint — Build Plan

**imgint** — image intelligence toolkit for ethical OSINT and digital forensics.

**Scope change from v1:** the tool no longer stops at metadata blocks. It extracts *every* recoverable signal from an image file — structural fingerprints, embedded artefacts, trailing data, and derived analytics — and correlates them into an evidence record.

---

## 0. Two things that changed, and one of them is a warning

### 0.1 You lost your best safety property

The previous architecture's central claim was **"we never decode pixels"** — which eliminated every image-decoder CVE class, every native dependency, and every licensing question at a stroke.

OSINT scope breaks that. Perceptual hashing, error-level analysis, OCR, and steganography detection all require actual pixel data. The decoder is back.

**This is not a detail. It is the single largest architectural regression in the new scope**, and it forces a decision you didn't previously have to make: decoding untrusted attacker-controlled images now happens inside your tool, using libraries with a documented history of remote code execution (libwebp CVE-2023-4863 being the most recent widely-exploited example).

The answer is **process isolation** — the decode stage runs in a separate, sandboxed, resource-capped subprocess that holds no credentials, no network, and no filesystem write access beyond a scratch directory. See ADR-004 in `ARCHITECTURE.md`. Structure it this way from commit one; retrofitting a sandbox is painful.

### 0.2 "Ethical" has to be architecture, not a README paragraph

An OSINT tool and a stalking tool differ only in governance. The same extraction pipeline serves a newsroom verifying a war-crime video and someone tracking an ex-partner. The distinguishing features are structural:

- **Authorization scope** — a signed engagement file that bounds what may be examined, loaded before any run, enforced by the pipeline
- **Audit log** — append-only, hash-chained, covering every file touched and every external lookup made
- **Minimisation** — analysers are opt-in, not opt-out; you collect what the investigation needs and nothing else
- **Bright lines in code** — the tool refuses certain operations regardless of flags

Your project's `security-reviewer` skill already states this: *"Confirm written authorization and rules of engagement before proceeding."* That constraint belongs in the pipeline, not just in the manual.

### 0.3 What this tool will not do

Written into the PRD as binding non-goals, enforced in code:

| Refused | Why |
|---|---|
| Automated face recognition or biometric matching | Special-category data under GDPR Art. 9; the clearest line between forensics and surveillance |
| Bulk scraping of platforms | ToS violation, often CFAA/IT Act exposure, and outside the tool's file-analysis remit |
| Automated cross-platform identity correlation of private individuals | This is deanonymisation-as-a-service, whatever it's called |
| Real-time location tracking of a person | Not investigation; harassment infrastructure |
| Any pipeline targeting minors | No legitimate version of this exists in a general-purpose tool |
| Operation without a loaded authorization scope | The control that makes all the others meaningful |

Being explicit about this makes the project *stronger* in review, not weaker. An OSINT tool with no stated limits reads as naïve; one with enforced limits reads as professional.

---

## 1. What "extract all data" actually means

Seven extraction tiers. Tiers 1–3 are lossless recovery of what is physically in the file. Tiers 4–7 are derived analysis with increasing interpretive uncertainty — and increasing risk of overclaiming.

### Tier 1 — Metadata blocks
EXIF, XMP (including Extended XMP across segments), IPTC-IIM, ICC, JFIF, C2PA/JUMBF manifests, PNG text chunks, GIF comment blocks. Covered by the previous architecture; carry it forward intact.

### Tier 2 — Structural fingerprints *(the highest-value new tier)*
Signals that survive metadata stripping, because most stripping tools remove metadata and leave encoder structure untouched.

| Signal | Where | What it tells you |
|---|---|---|
| Quantization tables | JPEG `DQT` (`FFDB`) | Characteristic per encoder and per quality setting. Camera firmware, Photoshop, WhatsApp, and Facebook all have distinguishable tables. |
| Huffman tables | JPEG `DHT` | Default vs optimised tables separate camera output from software re-encodes |
| Chroma subsampling | `SOF0` component sampling factors | 4:4:4 / 4:2:2 / 4:2:0 narrows the producing software |
| Segment/chunk order | Container walk | Encoders emit segments in characteristic order; deviation indicates a rewrite |
| Restart interval | `DRI` | Present in some camera encoders, absent in most software |
| PNG filter/compression strategy | `IDAT` analysis | Distinguishes libpng from optipng from ImageMagick |

Together these form an **encoder fingerprint**. A photo with all metadata removed still announces "produced by an iPhone, then re-encoded once by WhatsApp." That is often the single most useful output of the whole tool.

### Tier 3 — Embedded artefacts
- **EXIF thumbnail (IFD1)** — frequently *not* regenerated when the main image is edited. Comparing the thumbnail against a downscaled main image detects edits and occasionally recovers content that was cropped out of the visible image. Historically the source of several high-profile identifications.
- **MPF images** — JPEG `APP2` `MPF\0`: iPhone depth maps, Samsung secondary frames, HDR components.
- **Trailing data** — bytes after JPEG `FFD9` or PNG `IEND`. Appended archives (polyglot files), steganographic payloads, or app padding.
- **Preview images in RAW** — full-resolution JPEG previews embedded in CR2/NEF/ARW, often reflecting the *unedited* original.
- **Multiple ICC profiles** — more than one is a strong re-encode signal.

### Tier 4 — Cryptographic and perceptual hashing
- SHA-256 of the whole file (integrity, chain of custody)
- SHA-256 of the image data stream alone (detects metadata-only changes)
- Perceptual hashes: aHash, dHash, pHash, blockhash — for near-duplicate clustering **within your own corpus**

> Matching perceptual hashes against external databases (PhotoDNA and equivalents) requires restricted-access agreements and is out of scope. Say so.

### Tier 5 — Geospatial and temporal consistency
- GPS decoding, altitude, DOP, and timestamp
- **Offline** reverse geocoding against a local GeoNames dump — see §4, this is an OPSEC requirement, not a convenience
- Solar position computation (NOAA algorithm) from GPS + timestamp, giving expected azimuth and elevation for analyst-driven shadow comparison — the chronolocation technique
- Cross-checks: does `DateTimeOriginal` agree with `GPSDateStamp`? Does the timezone offset match the longitude? Does filesystem mtime precede capture time?

### Tier 6 — Tampering indicators *(handle with care)*
- Quantization table inconsistency across regions — suggests splicing
- Double-JPEG-compression artefacts in the DCT coefficient histogram
- Thumbnail/main divergence
- Metadata timeline contradictions (`ModifyDate` before `DateTimeOriginal`)
- C2PA manifest present but failing validation, or stripped where expected
- **Error Level Analysis** — include it, but see the warning in §4. ELA is the most misused technique in this field.

### Tier 7 — Content-derived signals
- OCR of visible text (signage, plates, documents) — sandboxed, opt-in
- Dominant colours, aspect ratio, entropy map
- LSB entropy anomalies as a *steganography indicator*, never as proof
- Container anomalies: illegal chunk ordering, unexpected extra chunks

**Every Tier 6 and 7 output must carry a confidence rating and a plain-language caveat.** A forensic tool that emits `"tampered": true` is worse than useless — it is actively dangerous, because someone will quote it.

---

## 2. /10X — ten tools this could be

| # | Angle | Pitch | Primary user | Risk posture |
|---|---|---|---|---|
| `0x01` | **Verification workbench** | Analyst-facing: one image in, a structured report of everything recoverable plus consistency checks and confidence ratings. | Journalists, fact-checkers | Low — analysis of held files |
| `0x02` | **Chain-of-custody evidence processor** | Hash on ingest, immutable working copies, hash-chained audit log, signed report suitable for an electronic-records certificate. | DFIR, law enforcement, legal | Low — governance is the product |
| `0x03` | **Privacy self-audit** | Point it at your own photos: here is exactly what you leak, ranked by sensitivity, with one-click removal. Defensive mirror of the offensive tool. | Consumers, security awareness | Very low |
| `0x04` | **Stripped-image attribution** | Given a photo with all metadata removed, infer the producing device and processing chain from encoder fingerprints alone. | Verification, forensics | Medium — needs a fingerprint corpus |
| `0x05` | **Corpus triage engine** | 50,000 images from a leak or seizure → cluster by device, near-duplicate group, and time; surface outliers. Analyst time is the bottleneck this solves. | DFIR, investigative journalism | Medium — needs strong scope control |
| `0x06` | **Manipulation triage** | Rank a batch by "worth a human look", combining Tier-6 indicators. Explicitly a triage aid, never a verdict. | Newsroom, moderation | High — overclaim risk |
| `0x07` | **Content-credential auditor** | C2PA manifest validation, provenance-chain reconstruction, detection of stripped credentials. Aligned with where the industry is heading. | Publishers, platforms | Low — standards-based |
| `0x08` | **Steganography screener** | Container anomalies, trailing data, LSB entropy, polyglot detection. Screening only, with explicit false-positive rates. | Blue team, CTF, malware triage | Medium |
| `0x09` | **Training range** | Ships with a labelled corpus and guided exercises: find the edit, identify the device, chronolocate the photo. Teaching product. | Education, CTF, coursework | Very low |
| `0x0A` | **Embeddable core + WASM** | The analysis library is the product; CLI, a browser tool that uploads nothing, and a triage server are all clients. | Reuse, portfolio | Low |

### Recommended combination

**Build `0x01` + `0x04` + `0x02`, structured as `0x0A`, with `0x03` as the shipped demo.**

Reasoning:

- `0x01` is the coherent product and the natural home for everything else.
- `0x04` is the genuine differentiator. Metadata extraction is a solved problem; **attribution from encoder fingerprints when metadata is gone is not**, and it is where the interesting engineering lives.
- `0x02` is what separates a script from a tool. Chain of custody is unglamorous, almost no student project has it, and it is the fastest route to being taken seriously.
- `0x03` is the demo that a non-technical audience immediately understands, and it reframes the whole project as defensive — which is both true and strategically sound.
- `0x0A` is structural: keep the library free of CLI concerns and the browser demo costs a weekend rather than a rewrite.

Hold `0x06` (manipulation triage) deliberately in reserve. It is the most attention-grabbing and the easiest to get catastrophically wrong.

---

## 3. Phases

### Phase 0 — Governance skeleton (3 days) — *do this first*
Authorization scope file format, append-only hash-chained audit log, evidence store with read-only originals and separate working copies. **No extraction code yet.**
**Exit:** every subsequent commit runs inside a governance frame that already exists, so it can never be bolted on later.

### Phase 1 — Container + metadata layer (2 weeks)
The two-layer registry from the previous architecture, carried forward unchanged: container readers emit opaque blocks, standard parsers interpret them.
**Exit:** Tier 1 output matches ExifTool on a 40-file corpus, divergences documented.

### Phase 2 — Structural fingerprints (2 weeks) — *the differentiator*
DQT/DHT extraction, subsampling, segment ordering, fingerprint hashing, and a seed reference corpus mapping fingerprints to known devices and processing chains.
**Exit:** correctly identifies the processing chain for 20 images whose metadata you stripped yourself.

### Phase 3 — Embedded artefacts (1 week)
Thumbnail extraction and comparison, MPF images, trailing data, RAW previews.
**Exit:** recovers the embedded thumbnail from an image whose visible content was cropped, and reports the divergence.

### Phase 4 — Sandboxed decode (1.5 weeks)
Subprocess isolation, seccomp/Job Object/sandbox-exec confinement, hashing and pixel analytics inside the sandbox only.
**Exit:** a crafted malicious image kills the sandbox process and the parent continues cleanly with a diagnostic.

### Phase 5 — Consistency and analysis (2 weeks)
Offline reverse geocoding, solar position, timeline cross-checks, tampering indicators — every output carrying a confidence rating and caveat.
**Exit:** an analyst who has never used the tool can read a report and correctly state what it does and does not establish.

### Phase 6 — Reporting (1 week)
Structured JSON, human-readable report, signed export with hash manifest.
**Exit:** a report that a lawyer could attach to an electronic-records certificate without redrafting it.

### Phase 7 — Ship (1 week)
CI matrix, binaries, `SECURITY.md`, `ETHICS.md`, threat model, labelled demo corpus.
**Exit:** a stranger installs it, runs it on the demo corpus, and correctly interprets the output within five minutes.

---

## 4. /what am I missing

### The sandbox regression *(most important)*
- Pixel decoding reintroduces the entire image-decoder CVE class. Isolate the decode stage in a subprocess with no network, no credentials, a scratch-only filesystem view, and hard memory and CPU caps.
- The sandbox must be the **default** path, not an optional flag. A safety control you can forget to enable is not a control.
- Fuzz across the process boundary: the parent must survive any child crash, hang, or OOM without losing the batch.

### OPSEC for the investigator *(the thing nobody warns you about)*
- **Every online lookup leaks your investigation.** Reverse-geocoding a target's coordinates through a commercial API tells that provider precisely what you are examining, when, and from where. Logs are subpoenable and sometimes breached.
- Therefore: **offline-first is a security requirement, not a performance optimisation.** Ship an offline GeoNames dataset. Any network call must be opt-in, individually logged in the audit trail, and visible in the report.
- Design for air-gapped operation. Serious analysts work that way, and it is a genuine differentiator.
- Do not phone home. No telemetry, no update check, no crash reporting. State this in the README.

### Evidence handling
- **Hash on ingest, before anything else touches the file.** SHA-256 of the original, recorded in the audit log, never recomputed from a working copy.
- **Never modify an original.** Open read-only; operate on copies; verify the original's hash again at the end of the run.
- **Hash-chain the audit log** so tampering is detectable — each entry includes the hash of the previous entry.
- **Record tool version and analysis timestamp in every report.** An analysis is not reproducible without them.
- **Electronic-records admissibility has formal requirements.** In India this is the certificate under the Bharatiya Sakshya Adhiniyam (which replaced the Indian Evidence Act §65B regime in 2023–24); other jurisdictions have equivalents. Design the report so it supplies what such a certificate needs. Verify the current requirements with a lawyer — do not rely on this document or on a general-purpose model for legal specifics.

### Analytical integrity
- **ELA is the most misused technique in image forensics.** It produces false positives constantly, is heavily dependent on the resave quality you choose, and says nothing meaningful about images that have been recompressed by a messaging app — which is most images. Include it if you like, but label it as an indicator requiring expert interpretation, never as evidence. Tools that present ELA as proof have contributed to real misidentifications.
- **Never emit a boolean verdict for a Tier-6 finding.** Emit an indicator, a confidence level, and a sentence explaining what would produce a false positive.
- **Absence of metadata is not evidence of tampering.** Every major platform strips metadata on upload. This is the single most common analytical error in amateur OSINT.
- **Encoder fingerprints identify software, not people.** "Produced by an iPhone" is a device class, not an individual.
- **Timestamps are trivially forgeable** and camera clocks are routinely wrong. Treat them as claims, not facts.
- **Your fingerprint corpus determines your accuracy.** Attribution is only as good as the reference data behind it, and it will degrade as new devices ship. Version the corpus and report which version produced a result.

### Legal grounding
- Establish a lawful basis before processing personal data: in India, the DPDP Act 2023; in the EU, GDPR Art. 6, with Art. 9 governing biometric data specifically.
- Publicly accessible does not mean lawfully processable. Different tests, different jurisdictions.
- Unauthorised access provisions (IT Act §43/§66 in India, CFAA in the US, Computer Misuse Act 1990 in the UK) bound how material may be obtained — the tool should assume lawful possession and say so.
- Have the authorization scope file record purpose, legal basis, data subject categories, retention period, and expiry. Then **enforce the expiry in code.**
- Build in data retention limits and a documented deletion path.

### Engineering
- **Corpus is the project.** Beyond the 40-file format corpus: images with metadata deliberately stripped, platform re-encodes (WhatsApp, Telegram, Facebook, Instagram), screenshots of photos, scans, known-edited pairs, and known-authentic controls. Label everything with ground truth.
- **Ground truth or it isn't science.** Every Tier-6 indicator needs a measured false-positive rate on your own labelled corpus, published in the docs. Without that number, the feature is a guess with a progress bar.
- **Provenance per finding**, not per file. Every field records which extractor produced it, from which byte offset, at what confidence.
- **Determinism.** Same input plus same version plus same corpus version must produce byte-identical output, or nothing is reproducible.
- **Structured output on stdout, diagnostics on stderr, versioned schema.** Unchanged from v1 and still non-negotiable.

### Presentation
- **Name it for what it does.** "imgint" or similar beats anything with "exif" in it, since metadata is now one tier of seven.
- **`ETHICS.md` alongside `SECURITY.md`.** State the bright lines, the authorization requirement, and the refused capabilities. This is what makes the project defensible in a viva and credible to real users.
- **Ship a labelled demo corpus.** It lets people evaluate the tool honestly and doubles as your test suite.
- **Write the caveats into the output itself,** not only the docs. Nobody reads the docs when they are quoting your report.

---

## 5. Document set

| File | Purpose |
|---|---|
| `PLAN.md` | This file — scope, extraction tiers, sequencing, gaps |
| `PRD.md` | Users, goals, binding non-goals, success metrics |
| `SRD.md` | Numbered functional and non-functional requirements |
| `SRS.md` | IEEE-830-style formal specification: interfaces, features, data dictionary |
| `ARCHITECTURE.md` | Component design, data flow, and ADRs with trade-off analysis |

> `SRD.md` and `SRS.md` overlap by design. The SRD is the requirement *catalogue* — what must be true, numbered and traceable. The SRS is the formal *specification* — external interfaces, stimulus/response behaviour, and the data dictionary. If your course expects only one, submit the SRS and keep the SRD as the internal tracking document.

---

## 6. Do this today

Take a photo from your phone. Strip every byte of metadata with `exiftool -all=`. Post it to WhatsApp, download it back, and strip it again.

Now open all three files in a hex editor and compare the `DQT` segments.

The tables will differ, and those differences will tell you the processing history of a file that claims to have no history at all. That is the entire thesis of Tier 2 — and it is the part of this project that is actually novel.
