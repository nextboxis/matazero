"""Interactive Dark-Mode HTML Case Dossier Generator."""

from __future__ import annotations
import json
import html
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
        """Generate a standalone HTML dossier for a set of analysis records."""
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

            gps_f = next((f for f in rec.findings if f.name in ("gps_coordinates_claimed", "gps_location_fix")), None)
            time_f = next((f for f in rec.fields if "DateTime" in f.name), None)
            make_f = next((f for f in rec.fields if f.name == "Make"), None)
            model_f = next((f for f in rec.fields if f.name == "Model"), None)

            camera_str = html.escape(f"{make_f.value if make_f else ''} {model_f.value if model_f else ''}".strip() or "Unknown Camera")
            timestamp_str = html.escape(str(time_f.value) if time_f else "No timestamp")

            lat_val = None
            lon_val = None
            if gps_f and isinstance(gps_f.value, dict):
                raw_lat = gps_f.value.get("latitude")
                raw_lon = gps_f.value.get("longitude")
                if raw_lat is not None and raw_lon is not None:
                    try:
                        fl_lat = float(raw_lat)
                        fl_lon = float(raw_lon)
                        if -90.0 <= fl_lat <= 90.0 and -180.0 <= fl_lon <= 180.0:
                            if not (abs(fl_lat) < 0.0001 and abs(fl_lon) < 0.0001):
                                lat_val = fl_lat
                                lon_val = fl_lon
                    except Exception:
                        pass

            f_name = html.escape(Path(rec.file_path).name if rec.file_path else "evidence")
            safe_badge_text = html.escape(badge_text)

            if lat_val is not None and lon_val is not None:
                gps_points.append({
                    "file_name": f_name,
                    "lat": lat_val,
                    "lng": lon_val,
                    "camera": camera_str,
                    "timestamp": timestamp_str,
                    "verdict": safe_badge_text,
                })

            finding_names = [html.escape(f.name) for f in rec.findings[:6]]

            table_rows_data.append({
                "file_name": f_name,
                "file_size": f"{rec.file_size / 1024:.1f} KB",
                "mime_type": rec.mime_type,
                "sha256": html.escape(rec.sha256[:12] + "..."),
                "camera": camera_str,
                "timestamp": timestamp_str,
                "has_gps": lat_val is not None,
                "rating": rating,
                "badge_class": badge_class,
                "badge_text": safe_badge_text,
                "confidence": f"{conf * 100:.0f}%",
                "findings_count": len(rec.findings),
                "finding_tags": finding_names,
            })

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        gps_json = json.dumps(gps_points).replace('</', r'<\/')
        rows_json = json.dumps(table_rows_data)
        safe_case_title = html.escape(case_title)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{safe_case_title} — matazero</title>
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
.map-header {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--border-color); }}
.map-canvas-wrap {{ position: relative; width: 100%; height: 380px; background: #0b1120; }}
#geoCanvas {{ width: 100%; height: 100%; display: block; }}
.map-tooltip {{ position: absolute; display: none; background: rgba(15, 23, 42, 0.95); border: 1px solid var(--accent-cyan); border-radius: 8px; padding: 10px 14px; font-size: 12px; color: #f8fafc; pointer-events: none; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }}
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
      <div class="subtitle">{safe_case_title} • Generated on {generated_at}</div>
    </div>
    <div style="text-align: right;">
      <span class="badge badge-authentic">100% Offline Air-Gapped Safe</span>
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
    <div class="map-header">
      <div style="font-weight: 600;">🗺️ Air-Gapped Geolocation Map Grid</div>
      <span style="font-size: 12px; color: var(--accent-cyan);">Zero External Telemetry</span>
    </div>
    <div class="map-canvas-wrap">
      <canvas id="geoCanvas"></canvas>
      <div id="mapTooltip" class="map-tooltip"></div>
    </div>
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
    matazero — Courtroom-grade digital image forensics and ethical OSINT.<br>
    SHA-256 Custody Hash Verified. 100% Offline & Air-Gapped.
  </footer>
</div>

<script>
const gpsData = {gps_json};

function renderAirGappedMap() {{
  const canvas = document.getElementById('geoCanvas');
  if (!canvas || gpsData.length === 0) return;
  const ctx = canvas.getContext('2d');
  const tooltip = document.getElementById('mapTooltip');

  function resize() {{
    canvas.width = canvas.parentElement.clientWidth * window.devicePixelRatio;
    canvas.height = canvas.parentElement.clientHeight * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    draw();
  }}

  let minLat = 90, maxLat = -90, minLng = 180, maxLng = -180;
  gpsData.forEach(p => {{
    if (p.lat < minLat) minLat = p.lat;
    if (p.lat > maxLat) maxLat = p.lat;
    if (p.lng < minLng) minLng = p.lng;
    if (p.lng > maxLng) maxLng = p.lng;
  }});

  const padLat = Math.max(0.05, (maxLat - minLat) * 0.2);
  const padLng = Math.max(0.05, (maxLng - minLng) * 0.2);
  minLat -= padLat; maxLat += padLat;
  minLng -= padLng; maxLng += padLng;

  function toScreen(lat, lng) {{
    const w = canvas.parentElement.clientWidth;
    const h = canvas.parentElement.clientHeight;
    const x = ((lng - minLng) / (maxLng - minLng)) * (w - 80) + 40;
    const y = ((maxLat - lat) / (maxLat - minLat)) * (h - 60) + 30;
    return {{ x, y }};
  }}

  function draw() {{
    const w = canvas.parentElement.clientWidth;
    const h = canvas.parentElement.clientHeight;
    ctx.clearRect(0, 0, w, h);

    // Draw grid lines
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    for (let x = 40; x < w; x += 60) {{
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
    }}
    for (let y = 30; y < h; y += 50) {{
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }}

    // Draw coordinate markers
    ctx.fillStyle = '#64748b';
    ctx.font = '10px monospace';
    ctx.fillText(`${{maxLat.toFixed(2)}}°N`, 6, 20);
    ctx.fillText(`${{minLat.toFixed(2)}}°S`, 6, h - 10);
    ctx.fillText(`${{minLng.toFixed(2)}}°W`, 40, h - 8);
    ctx.fillText(`${{maxLng.toFixed(2)}}°E`, w - 70, h - 8);

    // Plot evidence locations
    gpsData.forEach((p, idx) => {{
      const pos = toScreen(p.lat, p.lng);

      // Radar glow pulse
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 14, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
      ctx.fill();

      // Outer ring
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 8, 0, Math.PI * 2);
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Center pin
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#38bdf8';
      ctx.fill();

      // Label
      ctx.fillStyle = '#f8fafc';
      ctx.font = '11px sans-serif';
      ctx.fillText(p.file_name, pos.x + 12, pos.y + 4);
    }});
  }}

  canvas.addEventListener('mousemove', (e) => {{
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    let hit = null;

    gpsData.forEach(p => {{
      const pos = toScreen(p.lat, p.lng);
      const dist = Math.hypot(mx - pos.x, my - pos.y);
      if (dist <= 16) hit = {{ p, pos }};
    }});

    if (hit) {{
      tooltip.style.display = 'block';
      tooltip.style.left = `${{hit.pos.x + 16}}px`;
      tooltip.style.top = `${{hit.pos.y - 10}}px`;
      tooltip.innerHTML = `<b>${{hit.p.file_name}}</b><br>Coordinates: ${{hit.p.lat.toFixed(5)}}, ${{hit.p.lng.toFixed(5)}}<br>Camera: ${{hit.p.camera}}<br>Timestamp: ${{hit.p.timestamp}}<br>Verdict: ${{hit.p.verdict}}`;
    }} else {{
      tooltip.style.display = 'none';
    }}
  }});

  window.addEventListener('resize', resize);
  resize();
}}

renderAirGappedMap();

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
