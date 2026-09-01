"""Forensic Geolocation Data Exporter supporting GeoJSON, Leaflet HTML Maps, and GPX Tracks."""

from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class GeoExporter:
    """Exports structured geospatial evidence records into GeoJSON, Leaflet Maps, and GPX."""

    @staticmethod
    def to_geojson(
        points: List[Dict[str, Any]],
        title: str = "matazero Geolocation Evidence",
        geofence_geojson: Optional[str | Path | Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generates standard RFC 7946 GeoJSON FeatureCollection."""
        features = []
        coordinates_list = []

        for idx, pt in enumerate(points):
            lat = pt.get("latitude") or pt.get("y")
            lon = pt.get("longitude") or pt.get("x")
            if lat is None or lon is None:
                continue

            # IDEA 1: Skip Null Island coordinates in exports
            if abs(float(lat)) < 0.0001 and abs(float(lon)) < 0.0001:
                continue

            coordinates_list.append([lon, lat])
            props = {
                "id": idx + 1,
                "file_name": pt.get("file_name", f"Target_{idx+1}"),
                "file_path": str(pt.get("file_path", "")),
                "timestamp": pt.get("timestamp"),
                "altitude_m": pt.get("altitude_m"),
                "nearest_city": pt.get("closest_city") or pt.get("nearest_place"),
                "country": pt.get("country"),
                "timezone": pt.get("timezone"),
                "sha256": pt.get("sha256", ""),
                "camera_make": pt.get("camera_make"),
                "camera_model": pt.get("camera_model"),
            }
            # Clean None values
            props = {k: v for k, v in props.items() if v is not None}

            feature = {
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [lon, lat],
                },
                "properties": props,
            }
            features.append(feature)

        # If more than 1 point, add a trajectory LineString feature
        if len(coordinates_list) > 1:
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "LineString",
                    "coordinates": coordinates_list,
                },
                "properties": {
                    "name": "Chronological Movement Trajectory",
                    "total_points": len(coordinates_list),
                    "stroke": "#00ffcc",
                    "stroke-width": 3,
                },
            })

        # If geofence provided, append geofence polygon features
        if geofence_geojson:
            try:
                from imgint.core.geo.locator import GeoLocator
                gf_features = GeoLocator.load_geojson_features(geofence_geojson)
                for gf in gf_features:
                    features.append(gf)
            except Exception:
                pass

        # Calculate bounding box
        bbox = None
        if coordinates_list:
            min_lon = min(c[0] for c in coordinates_list)
            max_lon = max(c[0] for c in coordinates_list)
            min_lat = min(c[1] for c in coordinates_list)
            max_lat = max(c[1] for c in coordinates_list)
            bbox = [min_lon, min_lat, max_lon, max_lat]

        geojson_doc = {
            "type": "FeatureCollection",
            "metadata": {
                "generator": "matazero forensic geolocation engine v2.0",
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "title": title,
                "feature_count": len(points),
            },
            "features": features,
        }
        if bbox:
            geojson_doc["bbox"] = bbox
        return geojson_doc

    @staticmethod
    def to_leaflet_html(
        points: List[Dict[str, Any]],
        title: str = "matazero Forensic Geolocation Dossier",
        geofence_geojson: Optional[str | Path | Dict[str, Any]] = None,
    ) -> str:
        """Generates a standalone, rich interactive Leaflet / OpenStreetMap HTML Map."""
        valid_points = []
        for idx, pt in enumerate(points):
            lat = pt.get("latitude") or pt.get("y")
            lon = pt.get("longitude") or pt.get("x")
            if lat is not None and lon is not None:
                # IDEA 1: Skip Null Island coordinates in exports
                if abs(float(lat)) < 0.0001 and abs(float(lon)) < 0.0001:
                    continue
                item = dict(pt)
                item["lat"] = float(lat)
                item["lon"] = float(lon)
                item["idx"] = idx + 1

                # If geofence provided, check inside status
                if geofence_geojson:
                    try:
                        from imgint.core.geo.locator import GeoLocator
                        gf_res = GeoLocator.is_point_in_geofence(float(lat), float(lon), geofence_geojson)
                        item["inside_geofence"] = gf_res.get("inside_geofence", False)
                        item["geofence_boundary"] = gf_res.get("matched_feature_name")
                    except Exception:
                        pass

                valid_points.append(item)

        geofence_data_json = "null"
        if geofence_geojson:
            try:
                from imgint.core.geo.locator import GeoLocator
                gf_feats = GeoLocator.load_geojson_features(geofence_geojson)
                if gf_feats:
                    geofence_data_json = json.dumps({"type": "FeatureCollection", "features": gf_feats})
            except Exception:
                pass

        if not valid_points:
            center_lat, center_lon = 20.0, 0.0
            zoom = 2
        elif len(valid_points) == 1:
            center_lat, center_lon = valid_points[0]["lat"], valid_points[0]["lon"]
            zoom = 14
        else:
            center_lat = sum(p["lat"] for p in valid_points) / len(valid_points)
            center_lon = sum(p["lon"] for p in valid_points) / len(valid_points)
            zoom = 10

        points_json = json.dumps(valid_points)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        :root {{
            --bg: #0d1117;
            --panel: #161b22;
            --border: #30363d;
            --accent: #58a6ff;
            --text: #c9d1d9;
            --highlight: #00ffcc;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            display: flex;
            flex-direction: column;
            height: 100vh;
        }}
        header {{
            background: var(--panel);
            padding: 12px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            z-index: 1000;
        }}
        .brand {{ display: flex; align-items: center; gap: 12px; }}
        .brand h1 {{ font-size: 1.15rem; font-weight: 700; color: #fff; }}
        .brand span {{ background: #238636; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }}
        .stats {{ font-size: 0.85rem; color: #8b949e; }}
        #container {{ display: flex; flex: 1; position: relative; overflow: hidden; }}
        #map {{ flex: 1; height: 100%; z-index: 1; }}
        #sidebar {{
            width: 380px;
            background: var(--panel);
            border-left: 1px solid var(--border);
            overflow-y: auto;
            padding: 16px;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .point-card {{
            background: #0d1117;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .point-card:hover {{
            border-color: var(--accent);
            transform: translateY(-2px);
        }}
        .point-card.active {{
            border-color: var(--highlight);
            box-shadow: 0 0 10px rgba(0, 255, 204, 0.2);
        }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }}
        .card-header strong {{ color: #fff; font-size: 0.95rem; }}
        .card-header .badge {{ background: #1f6feb; color: #fff; font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; }}
        .card-row {{ font-size: 0.82rem; color: #8b949e; display: flex; justify-content: space-between; margin-top: 3px; }}
        .card-row span:last-child {{ color: var(--text); font-weight: 500; }}
        .leaflet-popup-content-wrapper {{ background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 8px; }}
        .leaflet-popup-tip {{ background: var(--panel); }}
        .popup-title {{ font-weight: bold; color: #fff; font-size: 1rem; margin-bottom: 6px; }}
        .popup-field {{ font-size: 0.8rem; margin: 3px 0; color: #8b949e; }}
        .popup-field b {{ color: var(--text); }}
        .popup-links {{ margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border); display: flex; gap: 8px; }}
        .popup-links a {{ font-size: 0.75rem; color: var(--accent); text-decoration: none; font-weight: bold; }}
        .popup-links a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <h1>🌐 {title}</h1>
            <span>EVIDENCE GRADE</span>
        </div>
        <div class="stats">
            Markers: <strong>{len(valid_points)}</strong> | Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
        </div>
    </header>
    <div id="container">
        <div id="map"></div>
        <div id="sidebar">
            <h3 style="color: #fff; font-size: 0.9rem; margin-bottom: 4px;">LOCATED ASSETS</h3>
            <div id="points-list" style="display: flex; flex-direction: column; gap: 8px;"></div>
        </div>
    </div>

    <script>
        const points = {points_json};
        const geofenceGeoJson = {geofence_data_json};
        
        // Tile Layers
        const osm = L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap contributors'
        }});

        const dark = L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
            attribution: '© CartoDB'
        }});

        const satellite = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
            attribution: '© Esri World Imagery'
        }});

        const map = L.map('map', {{
            center: [{center_lat}, {center_lon}],
            zoom: {zoom},
            layers: [dark]
        }});

        const baseMaps = {{
            "Dark Theme": dark,
            "OpenStreetMap": osm,
            "Satellite Imagery": satellite
        }};
        L.control.layers(baseMaps).addTo(map);

        const markers = [];
        const latlngs = [];
        const listContainer = document.getElementById('points-list');

        points.forEach((p, idx) => {{
            const latlng = [p.lat, p.lon];
            latlngs.push(latlng);

            const facSummary = (p.facility_proximity && p.facility_proximity.summary) || (p.facility_context && p.facility_context.summary) || '';
            const solar = p.solar_chronolocation || {{}};
            const ipCorr = p.ip_correlation || {{}};

            const popupContent = `
                <div class="popup-title">#${{p.idx}} ${{p.file_name || 'Evidence Asset'}}</div>
                <div class="popup-field">Coordinates: <b>${{p.lat.toFixed(6)}}°, ${{p.lon.toFixed(6)}}°</b></div>
                ${{p.closest_city ? `<div class="popup-field">Nearest City: <b>${{p.closest_city}}, ${{p.country || ''}}</b></div>` : ''}}
                ${{facSummary && facSummary !== 'No major aviation or maritime transit hub within immediate proximity.' ? `<div class="popup-field">Facility Context: <b style="color: #58a6ff;">${{facSummary}}</b></div>` : ''}}
                ${{solar.solar_elevation_degrees !== undefined ? `<div class="popup-field">Solar Chronolocation: <b>${{solar.day_phase || 'Solar'}} (El: ${{solar.solar_elevation_degrees}}°, Az: ${{solar.solar_azimuth_degrees}}°)</b></div>` : ''}}
                ${{ipCorr.correlation_verdict ? `<div class="popup-field">IP Correlation: <b style="${{ipCorr.is_suspicious ? 'color: #ff7b72;' : 'color: #3fb950;'}}">${{ipCorr.correlation_verdict}} (Δ ${{ipCorr.distance_km}}km)</b></div>` : ''}}
                ${{p.timestamp ? `<div class="popup-field">Capture Time: <b>${{p.timestamp}}</b></div>` : ''}}
                ${{p.altitude_m !== undefined && p.altitude_m !== null ? `<div class="popup-field">Altitude: <b>${{p.altitude_m}} m</b></div>` : ''}}
                ${{p.timezone ? `<div class="popup-field">Timezone: <b>${{p.timezone}}</b></div>` : ''}}
                <div class="popup-links">
                    <a href="https://www.google.com/maps?q=${{p.lat}},${{p.lon}}" target="_blank">Google Maps</a>
                    <a href="https://www.openstreetmap.org/?mlat=${{p.lat}}&mlon=${{p.lon}}#map=16/${{p.lat}}/${{p.lon}}" target="_blank">OSM</a>
                </div>
            `;

            const marker = L.marker(latlng).addTo(map).bindPopup(popupContent);
            markers.push(marker);

            // Create Sidebar Card
            const card = document.createElement('div');
            card.className = 'point-card';
            card.innerHTML = `
                <div class="card-header">
                    <strong>#${{p.idx}} ${{p.file_name || 'Asset'}}</strong>
                    <span class="badge">${{p.country_code || 'GPS'}}</span>
                </div>
                <div class="card-row">
                    <span>Coordinates:</span>
                    <span>${{p.lat.toFixed(4)}}°, ${{p.lon.toFixed(4)}}°</span>
                </div>
                ${{p.closest_city ? `
                <div class="card-row">
                    <span>Location:</span>
                    <span>${{p.closest_city}}</span>
                </div>` : ''}}
                ${{facSummary && facSummary !== 'No major aviation or maritime transit hub within immediate proximity.' ? `
                <div class="card-row">
                    <span>Facility:</span>
                    <span style="color: #58a6ff; font-size: 0.75rem; text-align: right; max-width: 220px;">${{facSummary}}</span>
                </div>` : ''}}
                ${{solar.day_phase ? `
                <div class="card-row">
                    <span>Solar:</span>
                    <span style="color: #d2a8ff;">${{solar.day_phase}} (${{solar.solar_elevation_degrees}}°)</span>
                </div>` : ''}}
                ${{p.timestamp ? `
                <div class="card-row">
                    <span>Timestamp:</span>
                    <span>${{p.timestamp}}</span>
                </div>` : ''}}
            `;

            card.addEventListener('click', () => {{
                map.flyTo(latlng, 15, {{ duration: 1.2 }});
                marker.openPopup();
                document.querySelectorAll('.point-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');
            }});

            listContainer.appendChild(card);
        }});

        // Draw flight/transit trajectory if multiple points
        if (latlngs.length > 1) {{
            const polyline = L.polyline(latlngs, {{
                color: '#00ffcc',
                weight: 3,
                opacity: 0.8,
                dashArray: '6, 8'
            }}).addTo(map);
            map.fitBounds(polyline.getBounds(), {{ padding: [50, 50] }});
        }}

        // Render Optical Viewing Frustum Cones
        points.forEach(p => {{
            const cone = p.optical_viewing_cone || p.viewing_cone;
            if (cone && cone.polygon_latlngs && cone.polygon_latlngs.length > 2) {{
                const conePolygon = L.polygon(cone.polygon_latlngs, {{
                    color: '#ff9900',
                    weight: 1.5,
                    opacity: 0.8,
                    fillColor: '#ff9900',
                    fillOpacity: 0.2
                }}).addTo(map);
                conePolygon.bindPopup(`<b>Camera Sightline & FOV Cone</b><br>Heading: ${{cone.heading_deg}}° (${{cone.heading_ref}})<br>HFOV: ${{cone.hfov_degrees}}°<br>Focal Length: ${{cone.focal_length_35mm || cone.focal_length_mm || '50'}}mm`);
            }}
        }});

        // Render Geofence Polygon layer if provided
        if (geofenceGeoJson && geofenceGeoJson.features && geofenceGeoJson.features.length > 0) {{
            const geofenceLayer = L.geoJSON(geofenceGeoJson, {{
                style: function(feature) {{
                    return {{
                        color: feature.properties.stroke || '#00ffcc',
                        weight: feature.properties['stroke-width'] || 2,
                        opacity: feature.properties['stroke-opacity'] || 0.85,
                        fillColor: feature.properties.fill || '#00ffcc',
                        fillOpacity: feature.properties['fill-opacity'] || 0.12,
                        dashArray: '4, 6'
                    }};
                }},
                onEachFeature: function(feature, layer) {{
                    if (feature.properties && feature.properties.name) {{
                        layer.bindPopup('<b>Geofence:</b> ' + feature.properties.name + '<br>' + (feature.properties.description || ''));
                    }}
                }}
            }}).addTo(map);
            L.control.layers(null, {{ "Forensic Geofence": geofenceLayer }}).addTo(map);
        }}
    </script>
</body>
</html>"""
        return html

    @staticmethod
    def to_kml(points: List[Dict[str, Any]], doc_name: str = "matazero 3D Geospatial Intelligence Dossier") -> str:
        """Generates standard OpenGIS KML 2.2 XML with 3D camera placemarks, heading, and trajectory tracks."""
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2">',
            '  <Document>',
            f'    <name>{doc_name}</name>',
            '    <Style id="cameraPin">',
            '      <IconStyle>',
            '        <color>ff00ffff</color>',
            '        <scale>1.2</scale>',
            '        <Icon><href>http://maps.google.com/mapfiles/kml/shapes/camera.png</href></Icon>',
            '      </IconStyle>',
            '    </Style>',
            '    <Style id="flightTrack">',
            '      <LineStyle>',
            '        <color>ffccff00</color>',
            '        <width>4</width>',
            '      </LineStyle>',
            '    </Style>',
        ]

        track_coords = []
        for idx, pt in enumerate(points):
            lat = pt.get("latitude") or pt.get("lat") or pt.get("y")
            lon = pt.get("longitude") or pt.get("lon") or pt.get("x")
            if lat is None or lon is None:
                continue
            if abs(float(lat)) < 0.0001 and abs(float(lon)) < 0.0001:
                continue

            alt = pt.get("altitude_m", 0.0) or 0.0
            name = pt.get("file_name", f"Evidence #{idx + 1}")
            time_str = pt.get("timestamp", "")
            city = pt.get("closest_city", "Unknown")
            country = pt.get("country", "")
            fac = pt.get("facility_proximity", {}).get("summary", "")
            solar = pt.get("solar_chronolocation", {})
            cone = pt.get("optical_viewing_cone", {})
            heading = cone.get("heading_deg", 0.0) if isinstance(cone, dict) else 0.0

            track_coords.append(f"{lon:.6f},{lat:.6f},{alt:.1f}")

            desc = f"<![CDATA["
            desc += f"<h3>{name}</h3>"
            desc += f"<p><b>Coordinates:</b> {lat:.6f}°, {lon:.6f}°</p>"
            desc += f"<p><b>Location:</b> {city}, {country}</p>"
            if time_str:
                desc += f"<p><b>Capture Time:</b> {time_str}</p>"
            if alt:
                desc += f"<p><b>Altitude:</b> {alt:.1f} m</p>"
            if fac:
                desc += f"<p><b>Facilities:</b> {fac}</p>"
            if solar:
                desc += f"<p><b>Solar:</b> {solar.get('day_phase', '')} (El: {solar.get('solar_elevation_degrees', '')}°)</p>"
            desc += f"]]>"

            lines.extend([
                '    <Placemark>',
                f'      <name>{name}</name>',
                f'      <description>{desc}</description>',
                '      <styleUrl>#cameraPin</styleUrl>',
                '      <Camera>',
                f'        <longitude>{lon:.6f}</longitude>',
                f'        <latitude>{lat:.6f}</latitude>',
                f'        <altitude>{max(10.0, float(alt))}</altitude>',
                f'        <heading>{heading}</heading>',
                '        <tilt>60</tilt>',
                '        <roll>0</roll>',
                '        <altitudeMode>relativeToGround</altitudeMode>',
                '      </Camera>',
                '      <Point>',
                '        <extrude>1</extrude>',
                '        <altitudeMode>relativeToGround</altitudeMode>',
                f'        <coordinates>{lon:.6f},{lat:.6f},{alt:.1f}</coordinates>',
                '      </Point>',
                '    </Placemark>',
            ])

        if len(track_coords) > 1:
            lines.extend([
                '    <Placemark>',
                '      <name>3D Movement Trajectory</name>',
                '      <styleUrl>#flightTrack</styleUrl>',
                '      <LineString>',
                '        <extrude>1</extrude>',
                '        <tessellate>1</tessellate>',
                '        <altitudeMode>relativeToGround</altitudeMode>',
                '        <coordinates>',
                '          ' + ' '.join(track_coords),
                '        </coordinates>',
                '      </LineString>',
                '    </Placemark>',
            ])

        lines.extend([
            '  </Document>',
            '</kml>',
        ])
        return '\n'.join(lines)

    @staticmethod
    def to_kmz(points: List[Dict[str, Any]], output_kmz_path: str | Path, doc_name: str = "matazero 3D Geospatial Intelligence Dossier") -> Path:
        """Packages KML into a compressed KMZ archive for Google Earth Pro."""
        import zipfile
        kml_content = GeoExporter.to_kml(points, doc_name=doc_name)
        out_p = Path(output_kmz_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(out_p, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('doc.kml', kml_content.encode('utf-8'))

        return out_p

    @staticmethod
    def to_gpx(points: List[Dict[str, Any]], track_name: str = "matazero Image Evidence Track") -> str:
        """Generates standard GPS Exchange Format (GPX 1.1) XML."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<gpx version="1.1" creator="matazero forensic toolkit v2.0" xmlns="http://www.topografix.com/GPX/1/1">',
            "  <metadata>",
            f"    <name>{track_name}</name>",
            f"    <time>{now_utc}</time>",
            "  </metadata>",
            "  <trk>",
            f"    <name>{track_name}</name>",
            "    <trkseg>",
        ]

        for pt in points:
            lat = pt.get("latitude") or pt.get("y")
            lon = pt.get("longitude") or pt.get("x")
            if lat is None or lon is None:
                continue

            # IDEA 1: Skip Null Island coordinates in exports
            if abs(float(lat)) < 0.0001 and abs(float(lon)) < 0.0001:
                continue

            ele = pt.get("altitude_m")
            time_s = pt.get("timestamp")
            name = pt.get("file_name", "Asset")

            lines.append(f'      <trkpt lat="{lat:.6f}" lon="{lon:.6f}">')
            if ele is not None:
                lines.append(f"        <ele>{ele:.1f}</ele>")
            if time_s:
                lines.append(f"        <time>{time_s}</time>")
            lines.append(f"        <name>{name}</name>")
            lines.append("      </trkpt>")

        lines.extend([
            "    </trkseg>",
            "  </trk>",
            "</gpx>",
        ])
        return "\n".join(lines)

    # Alias for export compatibility
    to_html = to_leaflet_html

