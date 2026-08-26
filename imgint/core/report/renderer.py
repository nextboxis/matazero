"""Report renderers (JSON, NDJSON, Table, Human-readable text report) per SRD FR-9.1 - FR-9.7."""

from __future__ import annotations
import json
from typing import Any, Dict, List, Optional
from imgint.core.model.record import AnalysisRecord
from imgint.core.model.finding import Finding, Confidence
from imgint.core.report.html_renderer import HtmlReportRenderer


class ReportRenderer:
    """Renders analysis records into structured and human-readable formats."""

    @staticmethod
    def render_html(records: List[AnalysisRecord]) -> str:
        """Renders interactive standalone HTML evidence dossier."""
        if not records:
            return "<html><body><h1>No records</h1></body></html>"
        return HtmlReportRenderer.render_html(records[0])

    @staticmethod
    def render_json(records: List[AnalysisRecord], indent: int = 2) -> str:
        if len(records) == 1:
            return json.dumps(records[0].to_dict(), indent=indent)
        return json.dumps([r.to_dict() for r in records], indent=indent)

    @staticmethod
    def render_ndjson(records: List[AnalysisRecord]) -> str:
        lines = [json.dumps(r.to_dict()) for r in records]
        return "\n".join(lines)

    @classmethod
    def _format_value(cls, name: str, val: Any) -> List[str]:
        """Format finding values into tidy, human-readable indented lines."""
        lines: List[str] = []
        if isinstance(val, dict):
            if name == "encoder_composite_fingerprint":
                fmt = val.get("format", "Unknown")
                h = val.get("composite_hash", "None")
                dqt = val.get("dqt_count", 0)
                qs = val.get("estimated_qualities", [])
                dht = val.get("dht_count", 0)
                ss = val.get("subsampling", "Unknown")
                seq = val.get("segment_sequence", [])
                seq_str = " -> ".join(seq[:8]) + (f" ... ({len(seq)} segments)" if len(seq) > 8 else "")
                lines.append(f"     Format:           {fmt}")
                lines.append(f"     Composite Hash:   {h}")
                lines.append(f"     DQT Tables:       {dqt} (Estimated Quality: {qs})")
                lines.append(f"     DHT Tables:       {dht}")
                lines.append(f"     Chroma Subsample: {ss}")
                lines.append(f"     Segment Sequence: {seq_str}")
                return lines
            elif name == "perceptual_hashes":
                ahash = val.get("ahash", "N/A")
                dhash = val.get("dhash", "N/A")
                phash = val.get("phash", "N/A")
                lines.append(f"     aHash (Average):    {ahash}")
                lines.append(f"     dHash (Difference): {dhash}")
                lines.append(f"     pHash (Perceptual): {phash}")
                lines.append(f"     Scope Constraint:   Corpus-internal near-duplicate clustering only (FR-5.4)")
                return lines
            elif name == "image_dimensions":
                w = val.get("width")
                h = val.get("height")
                ar = val.get("aspect_ratio")
                mode = val.get("mode")
                lines.append(f"     Dimensions:       {w} x {h} px (Aspect Ratio: {ar}, Mode: {mode})")
                return lines
            elif name == "dominant_color_palette":
                hex_c = val.get("dominant_hex")
                rgb = val.get("mean_rgb")
                lines.append(f"     Dominant Color:   {hex_c} (Mean RGB: {rgb})")
                return lines
            elif name == "lsb_entropy_screening":
                density = val.get("lsb_bit_density")
                anom = val.get("lsb_anomaly")
                anom_text = "Anomaly Flagged" if anom else "Normal (Consistent with natural sensor/texture noise)"
                lines.append(f"     LSB Bit Density:  {density}")
                lines.append(f"     Anomaly Status:   {anom_text}")
                return lines
            elif name == "gps_location_fix":
                lat = val.get("latitude")
                lon = val.get("longitude")
                alt = val.get("altitude_m")
                place = val.get("nearest_place")
                cc = val.get("country_code")
                lines.append(f"     Coordinates:      {lat}° N, {lon}° E")
                if place:
                    lines.append(f"     Location (Est):   {place}, {cc}")
                if alt is not None:
                    lines.append(f"     Altitude:         {alt} m")
                return lines
            elif name == "authenticity_verdict":
                auth = val.get("is_authentic")
                auth_str = "AUTHENTIC" if auth is True else ("NON-AUTHENTIC / MODIFIED" if auth is False else "INCONCLUSIVE")
                verdict = val.get("verdict_label", "UNKNOWN")
                conf = val.get("confidence_score", 0.0)
                risk = val.get("risk_level", "LOW")
                reasons = val.get("supporting_reasons", [])
                lines.append(f"     Status:           {auth_str}")
                lines.append(f"     Verdict:          {verdict}")
                lines.append(f"     Integrity Score:  {int(conf * 100)}%")
                lines.append(f"     Risk Assessment:  {risk}")
                if reasons:
                    lines.append(f"     Key Evidence:     {'; '.join(reasons)}")
                return lines
            elif name == "solar_chronolocation_angles":
                az = val.get("solar_azimuth_deg")
                el = val.get("solar_elevation_deg")
                sf = val.get("shadow_length_factor")
                lines.append(f"     Solar Azimuth:    {az}°")
                lines.append(f"     Solar Elevation:  {el}°")
                if sf is not None:
                    lines.append(f"     Shadow Factor:    {sf}")
                return lines
            else:
                for k, v in val.items():
                    k_title = k.replace("_", " ").title()
                    lines.append(f"     {k_title:17}: {v}")
                return lines
        elif isinstance(val, list):
            lines.append(f"     Items ({len(val)}): {', '.join(str(x) for x in val[:10])}")
            return lines
        else:
            lines.append(f"     Value:            {val}")
            return lines

    @classmethod
    def render_report(cls, record: AnalysisRecord) -> str:
        """Renders human-readable report leading with 'what this does not establish' section per FR-9.7 & ADR-008."""
        lines: List[str] = []
        lines.append("=" * 80)
        lines.append(f"matazero FORENSIC EVIDENCE REPORT — v{record.tool_version}")
        lines.append("=" * 80)
        lines.append(f"Target File:      {record.file_path}")
        lines.append(f"File Size:        {record.file_size:,} bytes")
        lines.append(f"Format:           {record.mime_type}")
        lines.append(f"SHA-256:          {record.sha256}")
        if record.data_stream_sha256:
            lines.append(f"Data Stream SHA:  {record.data_stream_sha256}")
        lines.append(f"Scope ID:         {record.scope_id or 'UNSCOPED / SELF-AUDIT'}")
        lines.append(f"Corpus Version:   {record.corpus_version}")
        lines.append(f"Timestamp (UTC):  {record.timestamp_utc}")
        lines.append("-" * 80)

        # Authenticity & Integrity Verdict Banner
        if record.authenticity_verdict:
            v = record.authenticity_verdict
            auth = v.get("is_authentic")
            auth_str = "AUTHENTIC ORIGINAL" if auth is True else ("MANIPULATION / PAYLOAD DETECTED" if auth is False else "INCONCLUSIVE (METADATA STRIPPED)")
            lines.append(f"\n⚖️  AUTHENTICITY VERDICT: [{auth_str}] — Score: {int(v.get('confidence_score', 0.5) * 100)}% (Risk: {v.get('risk_level')})")
            lines.append(f"   Verdict Classification : {v.get('verdict_label')}")
            for r in v.get("supporting_reasons", []):
                lines.append(f"   • {r}")
            lines.append("")
            lines.append("-" * 80)

        # ADR-008 & FR-9.7: Lead with "What This Does NOT Establish"
        lines.append("\n[!] FORENSIC CAVEATS & CERTAINTY LIMITS:")
        lines.append(" • Verdicts are calculated from container consistency, hardware quantization, and C2PA claims.")
        lines.append(" • Absence of metadata is standard on social platforms and does not prove malicious manipulation.")
        lines.append(" • All derived and indicative findings carry confidence ratings and caveats detailed below.\n")
        lines.append("-" * 80)

        # Group findings by Tier
        tiers: Dict[int, List[Finding]] = {i: [] for i in range(1, 8)}
        for f in record.findings:
            if 1 <= f.tier <= 7:
                tiers[f.tier].append(f)

        tier_info = {
            1: (
                "TIER 1 — METADATA BLOCKS & STRUCTURE",
                "No embedded metadata blocks found in container (EXIF/XMP/IPTC absent — typical of messaging and social media platforms)."
            ),
            2: (
                "TIER 2 — STRUCTURAL ENCODER FINGERPRINTS & ATTRIBUTION",
                "No structural quantization or Huffman tables detected."
            ),
            3: (
                "TIER 3 — EMBEDDED ARTEFACTS & TRAILING DATA",
                "No embedded preview thumbnails, MPF multi-picture frames, or trailing data detected."
            ),
            4: (
                "TIER 4 — CRYPTOGRAPHIC & PERCEPTUAL HASHES",
                "No cryptographic hashes computed."
            ),
            5: (
                "TIER 5 — GEOSPATIAL & TEMPORAL CONSISTENCY",
                "No GPS coordinates, camera timestamps, or chronolocation signals present in container."
            ),
            6: (
                "TIER 6 — FORENSIC INDICATORS & INTEGRITY CHECKS",
                "No timeline inversions, thumbnail divergence, or structural anomalies detected."
            ),
            7: (
                "TIER 7 — CONTENT-DERIVED SIGNALS",
                "No pixel-derived content signals computed."
            ),
        }

        for t in range(1, 8):
            title, default_msg = tier_info[t]
            findings_in_tier = tiers[t]

            lines.append(f"\n▶ {title}")
            lines.append("-" * 80)

            # Special case for Tier 1: if there are extracted metadata fields, list a summary
            if t == 1 and record.fields:
                lines.append(f" • Extracted Metadata Fields ({len(record.fields)} total):")
                for fld in record.fields[:15]:
                    lines.append(f"     {fld.name:24} : {fld.value} ({fld.block_kind})")
                if len(record.fields) > 15:
                    lines.append(f"     ... and {len(record.fields) - 15} additional fields preserved in structured output.")
                lines.append("")

            if not findings_in_tier and (t != 1 or not record.fields):
                lines.append(f" • [DEFAULT / ABSENT] {default_msg}\n")
                continue

            for f in findings_in_tier:
                conf_tag = f"[{f.confidence.value.upper()}]"
                lines.append(f" • {f.name} {conf_tag}")
                val_lines = cls._format_value(f.name, f.value)
                for vl in val_lines:
                    lines.append(vl)
                lines.append(f"   Extractor:  {f.extractor}")
                if f.caveat:
                    lines.append(f"   Caveat:     {f.caveat}")
                if f.provenance:
                    prov_str = f"Layer: {f.provenance.source_layer}"
                    if f.provenance.offset is not None:
                        prov_str += f", Offset: 0x{f.provenance.offset:X}"
                    lines.append(f"   Provenance: {prov_str}")
                lines.append("")

        if record.diagnostics:
            lines.append("\n▶ DIAGNOSTICS & ANOMALIES")
            lines.append("-" * 80)
            for d in record.diagnostics:
                lines.append(f" [{d.level.upper()}] ({d.source}): {d.message}")
            lines.append("")

        lines.append("=" * 80)
        lines.append("END OF EVIDENCE REPORT — PROVENANCE PRESERVED")
        lines.append("=" * 80)
        return "\n".join(lines)
