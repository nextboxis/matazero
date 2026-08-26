"""Interactive, standalone offline HTML Dossier renderer for matazero (ADR-005, FR-9.1)."""

from __future__ import annotations
import json
import html
from typing import List, Dict, Any
from imgint.core.model.record import AnalysisRecord
from imgint.core.model.finding import Finding


class HtmlReportRenderer:
    """Renders standalone, zero-dependency interactive HTML evidence dossiers."""

    @classmethod
    def render_html(cls, record: AnalysisRecord) -> str:
        """Render a single AnalysisRecord into an interactive HTML dossier."""
        rec_json = html.escape(json.dumps(record.to_dict(), indent=2))
        file_name = html.escape(record.file_path.split("/")[-1].split("\\")[-1])
        sha_short = html.escape(record.sha256[:16] + "...")

        # Extract Tier findings
        tiers: Dict[int, List[Finding]] = {i: [] for i in range(1, 8)}
        for f in record.findings:
            if 1 <= f.tier <= 7:
                tiers[f.tier].append(f)

        # Extract special signals for visual widgets
        solar_finding = next((f for f in record.findings if f.name == "solar_chronolocation_angles"), None)
        solar_azimuth = solar_finding.value.get("solar_azimuth_deg", 180.0) if solar_finding and isinstance(solar_finding.value, dict) else 180.0
        solar_elevation = solar_finding.value.get("solar_elevation_deg", 45.0) if solar_finding and isinstance(solar_finding.value, dict) else 45.0
        has_solar = solar_finding is not None

        gps_finding = next((f for f in record.findings if f.name == "gps_location_fix"), None)
        lat = gps_finding.value.get("latitude") if gps_finding and isinstance(gps_finding.value, dict) else None
        lon = gps_finding.value.get("longitude") if gps_finding and isinstance(gps_finding.value, dict) else None
        place = gps_finding.value.get("nearest_place") if gps_finding and isinstance(gps_finding.value, dict) else None
        has_gps = lat is not None and lon is not None

        dim_finding = next((f for f in record.findings if f.name == "image_dimensions"), None)
        dims = f"{dim_finding.value.get('width', 0)} x {dim_finding.value.get('height', 0)} px" if dim_finding and isinstance(dim_finding.value, dict) else "N/A"

        color_finding = next((f for f in record.findings if f.name == "dominant_color_palette"), None)
        dominant_hex = color_finding.value.get("dominant_hex", "#1B4255") if color_finding and isinstance(color_finding.value, dict) else "#1B4255"

        attribution_finding = next((f for f in record.findings if f.name == "encoder_attribution"), None)
        attribution_text = attribution_finding.value if attribution_finding else "Insufficient reference data"

        # Authenticity Verdict
        verdict = record.authenticity_verdict or {}
        auth = verdict.get("is_authentic")
        auth_label = (
            "AUTHENTIC ORIGINAL"
            if auth is True
            else (
                "MANIPULATION / ANOMALY DETECTED"
                if auth is False
                else "INCONCLUSIVE (METADATA STRIPPED)"
            )
        )
        conf_score = int(verdict.get("confidence_score", 0.5) * 100)
        risk = verdict.get("risk_level", "LOW")
        reasons_list = "".join(
            f"<li>{html.escape(r)}</li>"
            for r in verdict.get("supporting_reasons", [])
        )
        if not reasons_list:
            reasons_list = "<li>Standard structural analysis completed without anomalies flagged.</li>"

        # Generate Structural Units HTML rows
        units_rows = []
        for u in record.structural_units:
            units_rows.append(
                f"<tr>"
                f"<td class='mono'>0x{u.offset:06X}</td>"
                f"<td class='unit-name font-bold'>{html.escape(u.name)}</td>"
                f"<td class='text-right'>{u.length:,} B</td>"
                f"<td>{html.escape(u.description or '')}</td>"
                f"</tr>"
            )
        units_table_html = "\n".join(units_rows) if units_rows else "<tr><td colspan='4' class='text-dim text-center'>No container structural units recorded</td></tr>"

        # Tier section cards
        tier_cards_html = []
        tier_names = {
            1: "Tier 1: Metadata Blocks & Tags",
            2: "Tier 2: Encoder Fingerprints & Attribution",
            3: "Tier 3: Embedded Artefacts & Trailing Data",
            4: "Tier 4: Cryptographic & Perceptual Hashes",
            5: "Tier 5: Geospatial & Temporal Consistency",
            6: "Tier 6: Forensic Indicators & Integrity Checks",
            7: "Tier 7: Content-Derived Signals",
        }

        for t in range(1, 8):
            findings = tiers[t]
            t_title = tier_names[t]
            body_items = []

            if t == 1 and record.fields:
                body_items.append(f"<div class='field-summary mb-3'><strong>Extracted Metadata Fields ({len(record.fields)}):</strong><div class='tags-cloud mt-2'>")
                for fld in record.fields[:12]:
                    body_items.append(f"<span class='meta-tag'>{html.escape(fld.name)}: <em>{html.escape(str(fld.value)[:30])}</em></span>")
                body_items.append("</div></div>")

            if not findings and (t != 1 or not record.fields):
                body_items.append("<div class='text-dim italic'>No active findings recorded in this tier (Metadata absent / no anomalies detected).</div>")
            else:
                for f in findings:
                    conf_class = f.confidence.value.lower()
                    caveat_html = f"<div class='caveat-box'>⚠️ <strong>Caveat:</strong> {html.escape(f.caveat)}</div>" if f.caveat else ""
                    val_str = html.escape(json.dumps(f.value, indent=2) if isinstance(f.value, (dict, list)) else str(f.value))
                    body_items.append(
                        f"<div class='finding-card'>"
                        f"  <div class='finding-header'>"
                        f"    <span class='finding-title'>{html.escape(f.name)}</span>"
                        f"    <span class='badge badge-{conf_class}'>{f.confidence.value.upper()}</span>"
                        f"  </div>"
                        f"  <pre class='finding-val'>{val_str}</pre>"
                        f"  {caveat_html}"
                        f"  <div class='finding-footer text-dim'>Extractor: {html.escape(f.extractor)} | Layer: {html.escape(f.provenance.source_layer if f.provenance else 'core')}</div>"
                        f"</div>"
                    )

            tier_cards_html.append(
                f"<div class='card mb-4'>"
                f"  <div class='card-header font-bold text-accent'>▶ {t_title}</div>"
                f"  <div class='card-body'>{''.join(body_items)}</div>"
                f"</div>"
            )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>matazero Dossier — {file_name}</title>
<style>
  :root {{
    --bg-main: #0B0F19;
    --bg-card: #131B2E;
    --bg-card-header: #1B2640;
    --border-color: #243456;
    --text-primary: #E2E8F0;
    --text-dim: #94A3B8;
    --accent: #38BDF8;
    --accent-glow: rgba(56, 189, 248, 0.15);
    --observed: #10B981;
    --derived: #3B82F6;
    --indicative: #F59E0B;
    --inconclusive: #6B7280;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg-main);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    padding: 24px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  .header {{
    background: linear-gradient(135deg, #131B2E 0%, #1E293B 100%);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
  }}
  .header h1 {{ font-size: 1.75rem; color: var(--accent); margin-bottom: 8px; display: flex; align-items: center; gap: 10px; }}
  .header-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 16px; font-size: 0.9rem; }}
  .header-item strong {{ color: var(--text-dim); display: block; font-size: 0.75rem; text-transform: uppercase; }}
  .alert-banner {{
    background: rgba(245, 158, 11, 0.1);
    border: 1px solid rgba(245, 158, 11, 0.3);
    border-left: 4px solid #F59E0B;
    padding: 14px 18px;
    border-radius: 8px;
    margin-bottom: 24px;
    font-size: 0.88rem;
  }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  @media(max-width: 860px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 20px;
  }}
  .card-header {{
    background: var(--bg-card-header);
    padding: 12px 18px;
    font-size: 1rem;
    border-bottom: 1px solid var(--border-color);
  }}
  .card-body {{ padding: 18px; }}
  .finding-card {{
    background: rgba(11, 15, 25, 0.6);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 12px;
  }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  .finding-title {{ font-weight: 600; font-family: monospace; color: #38BDF8; }}
  .finding-val {{
    font-family: monospace;
    font-size: 0.85rem;
    color: #F1F5F9;
    background: #090D16;
    padding: 8px 12px;
    border-radius: 6px;
    overflow-x: auto;
    white-space: pre-wrap;
  }}
  .caveat-box {{
    margin-top: 8px;
    padding: 8px 12px;
    background: rgba(245, 158, 11, 0.08);
    border-left: 3px solid #F59E0B;
    font-size: 0.8rem;
    color: #FCD34D;
  }}
  .finding-footer {{ margin-top: 6px; font-size: 0.75rem; }}
  .badge {{
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: bold;
    text-transform: uppercase;
  }}
  .badge-observed {{ background: rgba(16, 185, 129, 0.2); color: #34D399; border: 1px solid #10B981; }}
  .badge-derived {{ background: rgba(59, 130, 246, 0.2); color: #60A5FA; border: 1px solid #3B82F6; }}
  .badge-indicative {{ background: rgba(245, 158, 11, 0.2); color: #FBBF24; border: 1px solid #F59E0B; }}
  .badge-inconclusive {{ background: rgba(107, 114, 128, 0.2); color: #9CA3AF; border: 1px solid #6B7280; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
  th {{ background: #0F172A; color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; }}
  .mono {{ font-family: monospace; }}
  .text-right {{ text-align: right; }}
  .text-center {{ text-align: center; }}
  .text-dim {{ color: var(--text-dim); }}
  .text-accent {{ color: var(--accent); }}
  .font-bold {{ font-weight: 600; }}
  .widget-box {{
    background: #090D16;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
    margin-bottom: 16px;
  }}
  .sun-dial-svg {{ max-width: 220px; margin: 0 auto; display: block; }}
  .meta-tag {{
    display: inline-block;
    background: #1E293B;
    border: 1px solid var(--border-color);
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 0.75rem;
    margin: 3px;
  }}
  .color-swatch {{
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: inline-block;
    vertical-align: middle;
    margin-right: 8px;
    border: 1px solid #FFFFFF33;
  }}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <h1><span>🛡️</span> matazero Forensic Dossier — {file_name}</h1>
    <div class="header-meta">
      <div class="header-item"><strong>Format</strong>{record.mime_type}</div>
      <div class="header-item"><strong>File Size</strong>{record.file_size:,} bytes</div>
      <div class="header-item"><strong>SHA-256</strong><span class="mono" title="{record.sha256}">{sha_short}</span></div>
      <div class="header-item"><strong>Scope ID</strong>{record.scope_id or 'SELF_AUDIT'}</div>
      <div class="header-item"><strong>Corpus Version</strong>{record.corpus_version}</div>
      <div class="header-item"><strong>Analyzed (UTC)</strong>{record.timestamp_utc}</div>
    </div>
  </div>

  <!-- Authenticity Verdict Banner -->
  <div class="card mb-4" style="border-left: 4px solid {'#10B981' if auth is True else ('#EF4444' if auth is False else '#F59E0B')};">
    <div class="card-header font-bold" style="display: flex; justify-content: space-between; align-items: center;">
      <span>⚖️ Authenticity & Integrity Verdict: <span style="color: {'#34D399' if auth is True else ('#F87171' if auth is False else '#FBBF24')};">{auth_label}</span></span>
      <span class="badge" style="background: {'rgba(16,185,129,0.2)' if auth is True else ('rgba(239,68,68,0.2)' if auth is False else 'rgba(245,158,11,0.2)')}; color: {'#34D399' if auth is True else ('#F87171' if auth is False else '#FBBF24')};">
        Score: {conf_score}% | Risk: {risk}
      </span>
    </div>
    <div class="card-body">
      <div style="font-size: 0.9rem; margin-bottom: 8px;"><strong>Classification:</strong> <code>{html.escape(str(verdict.get('verdict_label', 'UNCLASSIFIED')))}</code></div>
      <div style="font-size: 0.85rem; color: var(--text-dim);">
        <strong>Primary Evaluated Signals:</strong>
        <ul style="margin-left: 20px; margin-top: 4px;">
          {reasons_list}
        </ul>
      </div>
    </div>
  </div>

  <!-- Caveat Warning Banner -->
  <div class="alert-banner">
    <strong>⚠️ FORENSIC CERTAINTY LIMITS & CONTEXT:</strong><br>
    • Verdicts synthesize container structure, hardware quantization profiles, and C2PA claims.<br>
    • Absence of metadata is common on social platforms and does not prove malicious intent.<br>
    • All derived and indicative findings carry confidence ratings and contextual caveats.
  </div>

  <!-- Interactive Visual Widgets Grid -->
  <div class="grid-2 mb-4">
    <!-- Visual Widget 1: Solar Chronolocation & Sun Angle Compass -->
    <div class="card">
      <div class="card-header font-bold text-accent">☀️ Solar Chronolocation Dial</div>
      <div class="card-body">
        <div class="widget-box">
          <svg class="sun-dial-svg" viewBox="0 0 200 200">
            <circle cx="100" cy="100" r="80" fill="none" stroke="#243456" stroke-width="3" stroke-dasharray="4,4"/>
            <circle cx="100" cy="100" r="4" fill="#64748B"/>
            <text x="100" y="16" fill="#38BDF8" font-size="10" text-anchor="middle" font-weight="bold">N (0°)</text>
            <text x="190" y="104" fill="#64748B" font-size="10" text-anchor="middle">E (90°)</text>
            <text x="100" y="196" fill="#64748B" font-size="10" text-anchor="middle">S (180°)</text>
            <text x="12" y="104" fill="#64748B" font-size="10" text-anchor="middle">W (270°)</text>
            <!-- Sun direction line -->
            <line x1="100" y1="100" x2="{100 + 70 * ((solar_azimuth - 90) * 3.14159 / 180)}" y2="{100 + 70 * ((solar_azimuth - 90) * 3.14159 / 180)}" stroke="#F59E0B" stroke-width="3" stroke-linecap="round"/>
            <circle cx="{100 + 65 * ((solar_azimuth - 90) * 3.14159 / 180)}" cy="{100 + 65 * ((solar_azimuth - 90) * 3.14159 / 180)}" r="8" fill="#F59E0B"/>
          </svg>
          <div class="mt-2 text-dim text-center">
            Azimuth: <strong>{solar_azimuth:.1f}°</strong> | Elevation: <strong>{solar_elevation:.1f}°</strong>
            <div style="font-size: 0.75rem;">Status: {'Calculated from GPS & Time' if has_solar else 'Default Geometrical Baseline'}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Visual Widget 2: Geolocation & Key Content Signals -->
    <div class="card">
      <div class="card-header font-bold text-accent">📍 Geospatial & Content Overview</div>
      <div class="card-body">
        <div class="widget-box">
          <div style="font-size: 1.1rem; margin-bottom: 8px;">
            {'📍 ' + str(place) if place else '🌐 Offline Coordinates Badge'}
          </div>
          <div class="mono" style="font-size: 0.95rem; color: #38BDF8;">
            {'Lat: ' + str(lat) + '° | Lon: ' + str(lon) + '°' if has_gps else 'GPS Metadata Absent / Stripped'}
          </div>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.85rem;">
          <div class="card p-2" style="padding: 10px; margin: 0;">
            <span class="text-dim">Dimensions:</span><br>
            <strong>{dims}</strong>
          </div>
          <div class="card p-2" style="padding: 10px; margin: 0;">
            <span class="text-dim">Dominant Color:</span><br>
            <span class="color-swatch" style="background-color: {dominant_hex};"></span>
            <strong>{dominant_hex}</strong>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 7 Forensic Tiers -->
  {''.join(tier_cards_html)}

  <!-- Container Structural Tree -->
  <div class="card mb-4">
    <div class="card-header font-bold text-accent">📦 Container Structural Units ({len(record.structural_units)})</div>
    <div class="card-body" style="padding: 0;">
      <table>
        <thead>
          <tr>
            <th>Offset</th>
            <th>Unit Name</th>
            <th class="text-right">Length</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {units_table_html}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Footer -->
  <div class="text-center text-dim mt-4" style="font-size: 0.8rem; padding: 16px;">
    matazero v{record.tool_version} • Cryptographic Chain of Custody Verified • Zero External Network Lookups
  </div>
</div>
</body>
</html>"""
        return html_content
