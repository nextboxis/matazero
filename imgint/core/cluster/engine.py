"""Clustering engine for evidence grouping and outlier detection."""

from __future__ import annotations
import hashlib
import math
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

from imgint.core.pipeline import AnalysisPipeline
from imgint.core.governance.scope import AuthorizationScope
from imgint.core.model.record import AnalysisRecord


@dataclass
class ClusteredItem:
    file_name: str
    file_path: str
    sha256: str
    camera_make: Optional[str] = None
    camera_model: Optional[str] = None
    serial_number: Optional[str] = None
    dqt_hash: Optional[str] = None
    gps_coordinates: Optional[Tuple[float, float]] = None
    phash: Optional[str] = None
    risk_level: str = "LOW"
    is_outlier: bool = False
    outlier_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceCluster:
    cluster_id: str
    cluster_label: str
    strategy: str  # "camera", "dqt", "geo", "visual"
    item_count: int
    items: List[ClusteredItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["items"] = [it.to_dict() for it in self.items]
        return d


@dataclass
class ClusterReport:
    total_images: int
    strategy: str
    clusters: List[EvidenceCluster] = field(default_factory=list)
    outliers: List[ClusteredItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["clusters"] = [c.to_dict() for c in self.clusters]
        d["outliers"] = [o.to_dict() for o in self.outliers]
        return d


class ClusterEngine:
    """Groups evidence image sets by camera signature, DQT tables, geolocation, or perceptual similarity."""

    @classmethod
    def cluster(
        cls,
        targets: List[str | Path],
        strategy: str = "camera",
        geo_radius_km: float = 5.0,
        pipeline: Optional[AnalysisPipeline] = None,
    ) -> ClusterReport:
        if not pipeline:
            scope = AuthorizationScope.create_self_audit_scope()
            pipeline = AnalysisPipeline(scope=scope, selected_tiers={1, 2, 4, 5, 6})

        items: List[ClusteredItem] = []

        for t in targets:
            p = Path(t)
            if not p.is_file():
                continue
            try:
                rec = pipeline.analyze_file(p)
                item = cls._extract_clustered_item(p, rec)
                items.append(item)
            except Exception:
                pass

        if not items:
            return ClusterReport(total_images=0, strategy=strategy)

        clusters: List[EvidenceCluster] = []

        if strategy == "camera":
            clusters = cls._cluster_by_camera(items)
        elif strategy == "dqt":
            clusters = cls._cluster_by_dqt(items)
        elif strategy == "geo":
            clusters = cls._cluster_by_geo(items, geo_radius_km)
        elif strategy == "visual":
            clusters = cls._cluster_by_visual(items)
        else:
            clusters = cls._cluster_by_camera(items)

        # Detect Outliers (clusters with only 1 item while a major cluster exists)
        outliers: List[ClusteredItem] = []
        if len(clusters) > 1:
            main_cluster_size = max(c.item_count for c in clusters)
            if main_cluster_size >= 3:
                for c in clusters:
                    if c.item_count == 1:
                        outlier_item = c.items[0]
                        outlier_item.is_outlier = True
                        outlier_item.outlier_reason = f"Single anomaly outlier outside main fleet cluster ({c.cluster_label})"
                        outliers.append(outlier_item)

        return ClusterReport(
            total_images=len(items),
            strategy=strategy,
            clusters=clusters,
            outliers=outliers,
        )

    @classmethod
    def _extract_clustered_item(cls, path: Path, rec: AnalysisRecord) -> ClusteredItem:
        f_map = {f.name: f.value for f in rec.fields}
        make = str(f_map.get("Make")) if f_map.get("Make") else None
        model = str(f_map.get("Model")) if f_map.get("Model") else None
        serial = str(f_map.get("BodySerialNumber") or f_map.get("SerialNumber") or "")

        # DQT Hash
        dqt_bytes = bytearray()
        for u in rec.structural_units:
            if u.name == "DQT" and u.payload:
                dqt_bytes.extend(u.payload)
        dqt_hash = hashlib.md5(dqt_bytes).hexdigest()[:8] if dqt_bytes else "no_dqt"

        # GPS (Sanitized against bounds and Null Island)
        coords = None
        gps_finding = next((f for f in rec.findings if f.name in ("gps_coordinates_claimed", "gps_location_fix")), None)
        if gps_finding and isinstance(gps_finding.value, dict):
            lat = gps_finding.value.get("latitude")
            lon = gps_finding.value.get("longitude")
            if lat is not None and lon is not None:
                try:
                    f_lat, f_lon = float(lat), float(lon)
                    if -90.0 <= f_lat <= 90.0 and -180.0 <= f_lon <= 180.0:
                        if not (abs(f_lat) < 0.0001 and abs(f_lon) < 0.0001):
                            coords = (f_lat, f_lon)
                except Exception:
                    pass

        # Perceptual hash
        phash_f = next((f.value for f in rec.findings if f.name == "perceptual_hashes" and isinstance(f.value, dict)), {})
        phash = phash_f.get("phash") or phash_f.get("ahash")

        verdict_f = next((f.value for f in rec.findings if f.name == "authenticity_verdict" and isinstance(f.value, dict)), {})
        risk = verdict_f.get("risk_level", "LOW")

        return ClusteredItem(
            file_name=path.name,
            file_path=str(path),
            sha256=rec.sha256,
            camera_make=make,
            camera_model=model,
            serial_number=serial if serial else None,
            dqt_hash=dqt_hash,
            gps_coordinates=coords,
            phash=phash,
            risk_level=risk,
        )

    @classmethod
    def _cluster_by_camera(cls, items: List[ClusteredItem]) -> List[EvidenceCluster]:
        groups: Dict[str, List[ClusteredItem]] = {}
        for it in items:
            key_parts = []
            if it.camera_make or it.camera_model:
                key_parts.append(f"{it.camera_make or ''} {it.camera_model or ''}".strip())
            else:
                key_parts.append("Unknown / Stripped Camera")
            if it.serial_number:
                key_parts.append(f"SN:{it.serial_number}")
            if it.dqt_hash and it.dqt_hash != "no_dqt":
                key_parts.append(f"DQT:{it.dqt_hash}")
            k = " | ".join(key_parts)
            groups.setdefault(k, []).append(it)

        return [
            EvidenceCluster(
                cluster_id=f"CAM_{idx}",
                cluster_label=lbl,
                strategy="camera",
                item_count=len(g_items),
                items=g_items,
            )
            for idx, (lbl, g_items) in enumerate(groups.items(), start=1)
        ]

    @classmethod
    def _cluster_by_dqt(cls, items: List[ClusteredItem]) -> List[EvidenceCluster]:
        groups: Dict[str, List[ClusteredItem]] = {}
        for it in items:
            k = f"DQT_Profile_{it.dqt_hash}" if it.dqt_hash else "No_DQT_Table"
            groups.setdefault(k, []).append(it)

        return [
            EvidenceCluster(
                cluster_id=f"DQT_{idx}",
                cluster_label=lbl,
                strategy="dqt",
                item_count=len(g_items),
                items=g_items,
            )
            for idx, (lbl, g_items) in enumerate(groups.items(), start=1)
        ]

    @classmethod
    def _cluster_by_geo(cls, items: List[ClusteredItem], radius_km: float) -> List[EvidenceCluster]:
        geo_items = [it for it in items if it.gps_coordinates is not None]
        no_geo_items = [it for it in items if it.gps_coordinates is None]

        visited: Set[int] = set()
        clusters: List[EvidenceCluster] = []
        cluster_idx = 1

        for i, item in enumerate(geo_items):
            if i in visited:
                continue
            visited.add(i)
            group = [item]
            lat1, lon1 = item.gps_coordinates

            for j, other in enumerate(geo_items):
                if j in visited:
                    continue
                lat2, lon2 = other.gps_coordinates
                # Haversine distance
                dlat = math.radians(lat2 - lat1)
                dlon = math.radians(lon2 - lon1)
                a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
                c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
                dist = 6371.0 * c

                if dist <= radius_km:
                    visited.add(j)
                    group.append(other)

            clusters.append(
                EvidenceCluster(
                    cluster_id=f"GEO_{cluster_idx}",
                    cluster_label=f"Geospatial Zone (~{lat1:.4f}, {lon1:.4f}) within {radius_km}km",
                    strategy="geo",
                    item_count=len(group),
                    items=group,
                )
            )
            cluster_idx += 1

        if no_geo_items:
            clusters.append(
                EvidenceCluster(
                    cluster_id=f"GEO_NONE",
                    cluster_label="Non-Geolocated Evidence (No GPS)",
                    strategy="geo",
                    item_count=len(no_geo_items),
                    items=no_geo_items,
                )
            )

        return clusters

    @classmethod
    def _cluster_by_visual(cls, items: List[ClusteredItem]) -> List[EvidenceCluster]:
        visited: Set[int] = set()
        clusters: List[EvidenceCluster] = []
        cluster_idx = 1

        for i, item in enumerate(items):
            if i in visited:
                continue
            visited.add(i)
            group = [item]

            if item.phash:
                val1 = int(item.phash, 16)
                for j, other in enumerate(items):
                    if j in visited or not other.phash:
                        continue
                    val2 = int(other.phash, 16)
                    h_dist = bin(val1 ^ val2).count("1")
                    if h_dist <= 5:  # Near visual duplicate
                        visited.add(j)
                        group.append(other)

            clusters.append(
                EvidenceCluster(
                    cluster_id=f"VIS_{cluster_idx}",
                    cluster_label=f"Visual Scene Cluster {cluster_idx} (pHash: {item.phash or 'N/A'})",
                    strategy="visual",
                    item_count=len(group),
                    items=group,
                )
            )
            cluster_idx += 1

        return clusters
