# Forensic Integrity & Codebase Standards for matazero

When modifying, adding features, or debugging the matazero / imgint codebase, you MUST adhere to the following strict architectural and forensic standards:

1. **100% Offline Safety & Zero Telemetry (GR-4.1)**:
   - Never initiate outbound HTTP/socket network connections unless explicitly permitted by an authorized scope with network tier unlocked.
   - All parsers, hashers, and decoders must operate strictly on local byte buffers and memory.

2. **Bounded Reading & Memory Safety (AR-1.2)**:
   - Never use unbounded `.read()` on file handles. Always wrap access in `BoundedReader` with explicit offset and length limits.
   - Reject cyclic pointer traversal (EXIF IFD pointers, BMFF box offsets) using recursion limits (`depth <= 10`) and visited offset sets.

3. **Lossless Precision (FR-1.4)**:
   - Preserve exact integer fractions for rational EXIF/TIFF values (e.g. `(1, 250)` instead of `0.004`).
   - Retain exact byte offsets and raw slice bytes for all carved structures and payloads.

4. **Sandbox Isolation (SR-1.1)**:
   - All pixel decompression, SSIM calculations, and 2D FFT transforms must execute in the isolated sandbox worker process (`imgint.core.sandbox`).

5. **Chain of Custody & Audit Integrity (GR-2.1)**:
   - All mutating operations (cleaning, carving, extraction) must produce verifiable SHA-256 digests and log to the hash-chained audit logger.
