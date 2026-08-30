---
name: forensic-triaging
description: Guide and procedures for multi-tier evidence triaging, anomaly correlation, and confidence scoring using matazero.
---

# Forensic Evidence Triaging Procedure

Use this skill when analyzing suspect image evidence datasets or performing incident response on digital media.

## Step 1: Initial Fleet Triaging
Group all collected evidence to isolate distinct camera sources and surface statistical outliers:
```bash
python -m matazero cluster ./evidence/ -a --by camera
```

## Step 2: Full 7-Tier Deep Inspection
Run in-depth extraction over anomalous images:
```bash
python -m matazero analyze ./evidence/suspect.jpg -a --deep
```

## Step 3: Payload & Steganography Screening
1. **Trailing Payload Detection**:
   ```bash
   python -m matazero probe ./evidence/suspect.jpg
   python -m matazero extract payload ./evidence/suspect.jpg -o ./quarantine/
   ```
2. **Bitplane Slicing & Chi-Square PoV**:
   ```bash
   python -m matazero stego ./evidence/suspect.png -a --save-bitplanes ./bitplanes/
   ```

## Step 4: Timeline & Clock Drift Verification
Correlate camera RTC with GPS Satellite UTC timestamps:
```bash
python -m matazero timeline ./evidence/ -a -r -f plaso -o case_timeline.csv
```

## Step 5: Evidence Export
Index findings for database querying or threat intel sharing:
```bash
python -m matazero export sqlite ./evidence/ -a -o case_vault.db
python -m matazero export stix ./evidence/ -a -o threat_bundle.json
```
