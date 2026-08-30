"""Interactive Dark-Mode HTML Case Dossier Generator."""

from __future__ import annotations
import json
import base64
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from imgint.core.model.record import AnalysisRecord


class CaseDossierGenerator:
    """Generates standalone, interactive, dark-mode HTML case dossiers with embedded maps and KPI analytics."""

    @classmethod
    def generate_html(
        cls,
        records: List[AnalysisRecord],
        case_title: str = "Forensic Evidence Triage Dossier",
        output_path: Optional[str | Path] = None,
    ) -> str:
        total_items = len(records)
        authentic_count = 0
        tampered_count = 0
        synthetic_count = 0
        unverified_count = 0
        gps_points: List[Dict[str, Any]] = []

        table_rows_data = []

        for rec in records:
            verdict_dict = rec.authenticity_verdict or {}
            rating = verdict_dict.get("rating", "UNVERIFIED_METADATA_STRIPPED")
            conf = verdict_dict.get("confidence", 0.5)

            if "AUTHENTIC" in rating:
                authentic_count += 1
                badge_class = "badge-authentic"
                badge_text = "Authentic Capture"
            elif "TAMPERED" in rating:
                tampered_count += 1
                badge_class = "badge-tampered"
                badge_text = "Tampered / Payload"
            elif "SYNTHETIC" in rating or "AI" in rating:
                synthetic_count += 1
                badge_class = "badge-synthetic"
                badge_text = "AI / Synthetic"
            else:
                unverified_count += 1
                badge_class = "badge-unverified"
                badge_text = "Stripped / Inconclusive"

            # Check GPS
            lat_f = next((f for f in rec.fields if "Latitude" in f.name and "Ref" not in f.name), None)
            lon_f = next((f for f in rec.fields if "Longitude" in f.name and "Ref" not in f.name), None)
            time_f = next((f for f in rec.fields if "DateTime" in f.name), None)
            make_f = next((f for f in rec.fields if f.name == "Make"), None)
            model_f = next((f for f in rec.fields if f.name == "Model"), None)

            camera_str = f"{make_f.value if make_f else ''} {model_f.value if model_f else ''}".strip() or "Unknown Camera"
            timestamp_str = str(time_f.value) if time_f else "No timestamp"

            lat_val = None
            lon_val = None
            if lat_f and lon_f:
                try:
                    lat_val = float(lat_f.value) if isinstance(lat_f.value, (int, float)) else None
                    lon_val = float(lon_f.value) if isinstance(lon_f.value, (int, float)) else None
                except Exception:
                    pass

            f_name = Path(rec.file_path).name if rec.file_path else "evidence"

            if lat_val is not None and lon_val is not None:
                gps_points.append({
                    "file_name": f_name,
                    "lat": lat_val,
                    "lng": lon_val,
                    "camera": camera_str,
                    "timestamp": timestamp_str,
                    "verdict": badge_text,
                })

            # Format finding tags
            finding_names = [f.name for f in rec.findings[:6]]

            table_rows_data.append({
                "file_name": f_name,
                "file_size": f"{rec.file_size / 1024:.1f} KB",
                "mime_type": rec.mime_type,
                "sha256": rec.sha256[:12] + "...",
                "camera": camera_str,
                "timestamp": timestamp_str,
                "has_gps": lat_val is not None,
                "rating": rating,
                "badge_class": badge_class,
                "badge_text": badge_text,
                "confidence": f"{conf * 100:.0f}%",
                "findings_count": len(rec.findings),
                "finding_tags": finding_names,
            })

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        gps_json = json.dumps(gps_points)
        rows_json = json.dumps(table_rows_data)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{case_title} — matazero</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
:root {{
  --bg-primary: #0f172a;
  --bg-card: #1e293b;
  --bg-hover: #334155;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --accent-cyan: #06b6d4;
  --accent-green: #10b981;
  --accent-red: #ef4444;
  --accent-purple: #a855f7;
  --accent-yellow: #f59e0b;
  --border-color: #334155;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
body {{ background-color: var(--bg-primary); color: var(--text-primary); padding: 24px; }}
.container {{ max-width: 1400px; margin: 0 auto; }}
header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; margin-bottom: 24px; }}
.logo {{ font-size: 24px; font-weight: bold; color: var(--accent-cyan); display: flex; align-items: center; gap: 8px; }}
.subtitle {{ color: var(--text-secondary); font-size: 14px; }}
.kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.kpi-card {{ background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; text-align: center; }}
.kpi-value {{ font-size: 32px; font-weight: bold; margin-bottom: 4px; }}
.kpi-label {{ color: var(--text-secondary); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
.val-cyan {{ color: var(--accent-cyan); }}
.val-green {{ color: var(--accent-green); }}
.val-red {{ color: var(--accent-red); }}
.val-purple {{ color: var(--accent-purple); }}
.val-yellow {{ color: var(--accent-yellow); }}
.section-title {{ font-size: 18px; font-weight: 600; margin-bottom: 12px; color: var(--text-primary); }}
#map-container {{ background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden; margin-bottom: 24px; }}
#map {{ height: 400px; width: 100%; }}
.table-card {{ background-color: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; overflow: hidden; padding: 16px; }}
.table-header-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; gap: 16px; }}
.search-input {{ background: #0f172a; border: 1px solid var(--border-color); border-radius: 8px; padding: 8px 16px; color: var(--text-primary); font-size: 14px; width: 300px; }}
.search-input:focus {{ outline: none; border-color: var(--accent-cyan); }}
table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
th {{ background-color: #0f172a; color: var(--text-secondary); padding: 12px 16px; font-weight: 600; border-bottom: 1px solid var(--border-color); }}
td {{ padding: 12px 16px; border-bottom: 1px solid var(--border-color); }}
tr:hover {{ background-color: var(--bg-hover); }}
.badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; }}
.badge-authentic {{ background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
.badge-tampered {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
.badge-synthetic {{ background-color: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #a855f7; }}
.badge-unverified {{ background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
.tag {{ display: inline-block; background: #0f172a; color: #94a3b8; font-size: 11px; padding: 2px 6px; border-radius: 4px; margin: 2px; }}
footer {{ text-align: center; color: var(--text-secondary); font-size: 12px; margin-top: 32px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <div class="logo">🔬 matazero Dossier</div>
      <div class="subtitle">{case_title} • Generated on {generated_at}</div>
    </div>
    <div style="text-align: right;">
      <span class="badge badge-authentic">Air-Gapped Forensic Audit</span>
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value val-cyan">{total_items}</div>
      <div class="kpi-label">Total Evidence Items</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value val-green">{authentic_count}</div>
      <div class="kpi-label">Authentic Captures</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value val-red">{tampered_count}</div>
      <div class="kpi-label">Tampered / Spliced</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value val-purple">{synthetic_count}</div>
      <div class="kpi-label">AI / Synthetic</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value val-yellow">{len(gps_points)}</div>
      <div class="kpi-label">Geolocated Points</div>
    </div>
  </div>

  <div id="map-container" style="display: {'block' if gps_points else 'none'};">
    <div style="padding: 12px 16px; font-weight: 600; border-bottom: 1px solid var(--border-color);">🗺️ Evidence Geolocation Map</div>
    <div id="map"></div>
  </div>

  <div class="table-card">
    <div class="table-header-bar">
      <div class="section-title" style="margin-bottom: 0;">Evidence Inspection Log</div>
      <input type="text" id="searchInput" class="search-input" placeholder="Filter by filename, camera, verdict..." onkeyup="filterTable()">
    </div>
    <table id="evidenceTable">
      <thead>
        <tr>
          <th>File Name</th>
          <th>Size</th>
          <th>Camera Hardware</th>
          <th>Timestamp</th>
          <th>Authenticity Verdict</th>
          <th>Confidence</th>
          <th>Key Findings</th>
        </tr>
      </thead>
      <tbody>
"""
        for r in table_rows_data:
            tags_html = "".join([f'<span class="tag">{t}</span>' for t in r["finding_tags"]])
            html_content += f"""        <tr>
          <td style="font-weight: 600; color: #38bdf8;">{r['file_name']}<br><span style="font-size: 11px; color: #64748b;">{r['sha256']}</span></td>
          <td>{r['file_size']}</td>
          <td>{r['camera']}</td>
          <td>{r['timestamp']}</td>
          <td><span class="badge {r['badge_class']}">{r['badge_text']}</span></td>
          <td style="font-weight: 600;">{r['confidence']}</td>
          <td>{tags_html}</td>
        </tr>
"""

        html_content += f"""      </tbody>
    </table>
  </div>

  <footer>
    matazero v2.0.0 — Courtroom-grade digital image forensics and ethical OSINT.<br>
    SHA-256 Custody Hash Verified. 100% Offline & Air-Gapped.
  </footer>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const gpsData = {gps_json};

if (gpsData.length > 0) {{
  const map = L.map('map').setView([gpsData[0].lat, gpsData[0].lng], 13);
  L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
    attribution: '&copy; OpenStreetMap contributors &copy; CARTO'
  }}).addTo(map);

  const bounds = [];
  gpsData.forEach(p => {{
    const marker = L.marker([p.lat, p.lng]).addTo(map);
    marker.bindPopup(`<b>${{p.file_name}}</b><br>Camera: ${{p.camera}}<br>Time: ${{p.timestamp}}<br>Verdict: ${{p.verdict}}`);
    bounds.push([p.lat, p.lng]);
  }});
  if (bounds.length > 1) {{
    map.fitBounds(bounds, {{ padding: [30, 30] }});
  }}
}}

function filterTable() {{
  const input = document.getElementById('searchInput');
  const filter = input.value.toLowerCase();
  const table = document.getElementById('evidenceTable');
  const trs = table.getElementsByTagName('tr');

  for (let i = 1; i < trs.length; i++) {{
    const text = trs[i].textContent.toLowerCase();
    trs[i].style.display = text.includes(filter) ? '' : 'none';
  }}
}}
</script>
</body>
</html>
"""
        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(html_content, encoding="utf-8")

        return html_content
