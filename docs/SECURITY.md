# Security Policy & Architecture — imgint

## 1. Threat Model & Security Properties

`imgint` is designed specifically to analyze files that may be untrusted, corrupted, or hostile.

### 1.1 Process Isolation for Pixel Decoding (ADR-004)
- **Problem**: Image decoding libraries (libwebp, libjpeg, libheif, ImageMagick) have historically suffered from critical remote code execution (RCE) vulnerabilities.
- **Control**: All pixel-level decoding (Pillow / ImageHash / ELA / dominant color / LSB entropy calculation) is strictly executed inside an isolated, resource-capped child subprocess (`imgint.core.sandbox.worker`).
- **Blast Radius**: The child process runs with no credentials, no network access, and strict timeout boundaries. If a decoder crashes, hangs, or encounters an Out-Of-Memory condition, the parent orchestrator intercepts the termination and marks the finding as partial without compromising the evidence store.

### 1.2 Strict Bounds & Allocation Checks (NFR-1.4, NFR-1.5, NFR-1.6)
- Every read operation is bounded by `BoundedReader` with explicit length checks against file boundaries.
- Sizing allocations directly from untrusted image headers is prohibited.
- Structural recursion depth is hard-capped at 16, and unit count is capped at 4096 to prevent zip bombs, recursion loops, and parser memory bombs.

### 1.3 Safe XML / XMP Parsing (NFR-1.7)
- XMP RDF/XML parsing disables external entity resolution (XXE) and expands only bounded text nodes.

### 1.4 Cryptographic Chain of Custody (GR-2.1 - GR-2.8)
- Input files are hashed (SHA-256) on ingest and stored read-only.
- All analytical work is performed on isolated working copies.
- Re-verification of all original hashes is enforced before completion (Exit code 7 on mismatch).
- The audit log is append-only and cryptographically hash-chained (`sha256(previous_hash + entry)`).

### 1.5 Operational Security (OPSEC) (GR-4.1 - GR-4.6)
- **Offline by default**: Zero network calls, telemetry, update checks, or crash reporting.
- Reverse geocoding runs entirely offline against a local bundled dataset (`geonames_offline.json`).
- If `--allow-network` is explicitly passed, every external lookup is logged to the audit trail and rendered as a disclosure event in the final report.

## 2. Reporting a Vulnerability

Please report security issues responsibly to the maintainers.
