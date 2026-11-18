# Security Policy & Architecture — imgint

## 1. Threat Model & Security Properties

`imgint` is designed specifically to analyze files that may be untrusted, corrupted, or hostile.

### 1.1 Process Isolation for Pixel Decoding (ADR-004)
- **Problem**: Image decoding libraries (libwebp, libjpeg, libheif, ImageMagick) have historically suffered from critical remote code execution (RCE) vulnerabilities.
- **Control**: All pixel-level decoding (Pillow / ImageHash / ELA / dominant color / LSB entropy calculation) is strictly executed inside an isolated, resource-capped child subprocess (`imgint.core.sandbox.worker`) with a 64 MP decompression bomb ceiling (`Image.MAX_IMAGE_PIXELS = 64_000_000`) and path-traversal guards on crop output paths.
- **Blast Radius**: The child process runs with a scrubbed environment (all `*KEY*`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*CREDENTIAL*`, and `*PROXY*` variables removed, `PYTHONNOUSERSITE=1`, `NO_PROXY=*`), no network access, and strict timeout boundaries. If a decoder crashes, hangs, or encounters an Out-Of-Memory condition, the parent orchestrator intercepts the termination and marks the finding as partial without compromising the evidence store.

### 1.2 Strict Bounds & Allocation Checks (NFR-1.4, NFR-1.5, NFR-1.6)
- Every read operation is bounded by `BoundedReader` with explicit length checks against file boundaries.
- Sizing allocations directly from untrusted image headers is prohibited.
- Structural recursion depth is hard-capped at 16, and unit count is capped at 4096 to prevent zip bombs, recursion loops, and parser memory bombs.
- PNG `zTXt`/`iTXt` zlib decompression is hard-capped at 1 MB via streaming `zlib.decompressobj`, and Office OpenXML (`.pptx`, `.docx`, `.xlsx`) archives enforce per-entry (16 MB), cumulative (64 MB), and compression-ratio (`100x`) limits plus Zip Slip (`..`) rejection.

### 1.3 Safe XML / XMP & HTML/KML Sanitization (NFR-1.7)
- XMP RDF/XML and Office OpenXML parsers reject `<!DOCTYPE` and `<!ENTITY` declarations upfront (XXE & Billion Laughs prevention) and enforce a 2 MB XML payload ceiling.
- All HTML dossiers, Leaflet maps, KML, and GPX exports apply strict context-aware escaping (`html.escape`, `</script>` neutralization, and CDATA `]]>` sanitization) to prevent Stored XSS.

### 1.4 Cryptographic Chain of Custody & Scope Integrity (GR-2.1 - GR-2.8)
- Input files are hashed (SHA-256) on ingest and stored read-only; re-ingesting an existing file verifies the stored original hash before proceeding.
- All analytical work is performed on isolated working copies.
- Re-verification of all original hashes is enforced before completion (Exit code 7 on mismatch).
- The audit log is append-only and cryptographically hash-chained (`sha256(previous_hash + entry)`).
- Authorization scopes enforce constant-time `hmac.compare_digest` verification, reject external `is_self_audit: true` privilege escalation, and enforce refusal rules across all modes and dynamic skills.

### 1.5 Operational Security (OPSEC) (GR-4.1 - GR-4.6)
- **Offline by default**: Zero network calls, telemetry, update checks, or crash reporting.
- `OllamaClient` enforces HTTP/HTTPS schemes and restricts connections to loopback addresses (`localhost`, `127.0.0.1`, `::1`, `host.docker.internal`) by default to block SSRF and local file disclosure (`file://`).
- Reverse geocoding runs entirely offline against a local bundled dataset (`geonames_offline.json`) and the local Natural Earth Vector SQLite database.
- If `--allow-network` is explicitly passed, external IP lookups validate public routable IP addresses via `ipaddress` and every external lookup is logged to the audit trail.

## 2. Reporting a Vulnerability

Please report security issues responsibly to the maintainers.
