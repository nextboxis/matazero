"""Authenticity and Integrity Verdict Evaluator for matazero."""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from imgint.core.model.record import AnalysisRecord


@dataclass
class AuthenticityVerdict:
    is_authentic: Optional[bool]
    verdict_label: str  # e.g. "AUTHENTIC_ORIGINAL", "TAMPERED", "AI_OR_EDITED", "UNVERIFIED_STRIPPED"
    confidence_score: float  # 0.0 to 1.0
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    integrity_flags: Dict[str, bool]
    supporting_reasons: List[str]
    forensic_caveats: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuthenticityEvaluator:
    """Computes an evidence-grounded boolean authenticity verdict and integrity rating."""

    @classmethod
    def evaluate(cls, record: AnalysisRecord) -> AuthenticityVerdict:
        reasons: List[str] = []
        caveats: List[str] = []
        flags: Dict[str, bool] = {
            "container_intact": True,
            "metadata_present": bool(record.fields),
            "timeline_consistent": True,
            "hardware_encoder_match": False,
            "ai_generation_detected": False,
            "steganography_suspected": False,
            "trailing_payload_detected": False,
            "c2pa_signed": False,
        }

        score = 0.5
        is_authentic: Optional[bool] = None
        risk_level = "LOW"

        # 1. Check for trailing data / payloads (Tier 3)
        trailing_data_f = next((f for f in record.findings if f.name == "trailing_data_detected"), None)
        has_trailing = trailing_data_f is not None or any(u.name == "TRAILING_DATA" for u in record.structural_units)
        if has_trailing:
            flags["container_intact"] = False
            flags["trailing_payload_detected"] = True
            reasons.append("Container has trailing data or embedded payload past the file termination marker (EOI/IEND).")
            risk_level = "HIGH"
            score -= 0.35

        # 2. Check for Timeline Inversions (Tier 6)
        timeline_f = next((f for f in record.findings if f.name == "indicator_timeline_inversion"), None)
        if timeline_f:
            flags["timeline_consistent"] = False
            reasons.append("ModifyDate chronologically precedes DateTimeOriginal (timeline contradiction).")
            risk_level = "MEDIUM" if risk_level != "HIGH" else "HIGH"
            score -= 0.2

        # 3. Check LSB Entropy Steganography Screening (Tier 7)
        lsb_f = next((f for f in record.findings if f.name == "lsb_entropy_screening"), None)
        if lsb_f and isinstance(lsb_f.value, dict):
            is_anomaly = lsb_f.value.get("lsb_anomaly", False) or "High Density" in str(lsb_f.value.get("Anomaly Status", ""))
            if is_anomaly:
                flags["steganography_suspected"] = True
                reasons.append("High LSB entropy density detected (potential steganographic carrier or dense texture).")
                score -= 0.15

        # 4. Check Encoder Attribution (Tier 2)
        attr_f = next((f for f in record.findings if f.name == "encoder_attribution"), None)
        if attr_f and isinstance(attr_f.value, dict):
            model = attr_f.value.get("device_model") or attr_f.value.get("Device Model", "")
            encoder = attr_f.value.get("encoder_software") or attr_f.value.get("Encoder Software", "")
            sim = attr_f.value.get("similarity_score") or attr_f.value.get("Similarity Score", 0.0)

            if "Midjourney" in model or "Stable Diffusion" in model or "DALL-E" in model:
                flags["ai_generation_detected"] = True
                reasons.append(f"Quantization & structure match Generative AI pipeline ({model}).")
                score = 0.1
                risk_level = "HIGH"
                is_authentic = False
            elif "Photoshop" in model or "Lightroom" in model or "GIMP" in model:
                reasons.append(f"Quantization tables match post-processing editing suite ({model}).")
                score = 0.4
                risk_level = "MEDIUM"
                is_authentic = False
            elif any(k in model for k in ("iPhone", "Galaxy", "Pixel", "Canon", "Nikon", "Sony", "Fujifilm", "Xiaomi")):
                flags["hardware_encoder_match"] = True
                reasons.append(f"Quantization profile matches native camera hardware ISP ({model}).")
                score += 0.25
            elif "WhatsApp" in model or "Telegram" in model or "Twitter" in model or "Discord" in model:
                reasons.append(f"Quantization matches social media / messaging re-encoder ({model}).")
                score = 0.5

        # 5. Check C2PA Authenticity Manifest (Tier 1)
        c2pa_f = next((f for f in record.findings if f.name == "c2pa_manifest_presence"), None)
        if c2pa_f and isinstance(c2pa_f.value, dict) and c2pa_f.value.get("present"):
            flags["c2pa_signed"] = True
            gen = c2pa_f.value.get("claim_generator", "Unknown")
            actions = c2pa_f.value.get("actions_history", [])
            reasons.append(f"C2PA authenticity manifest present (Claim Generator: {gen}, Actions: {len(actions)}).")
            score += 0.2

        # 6. Check Metadata Presence & Coherence (Tier 1 & 5)
        gps_f = next((f for f in record.findings if f.name in ("gps_coordinates_claimed", "gps_location_fix")), None)
        if gps_f:
            reasons.append("GPS geolocation fix embedded in container metadata.")
            score += 0.1

        # Determine Verdict
        score = max(0.0, min(1.0, score))

        if flags["trailing_payload_detected"]:
            is_authentic = False
            verdict_label = "TAMPERED_TRAILING_PAYLOAD"
            risk_level = "CRITICAL"
        elif flags["ai_generation_detected"]:
            is_authentic = False
            verdict_label = "AI_SYNTHETIC_GENERATION"
            risk_level = "HIGH"
        elif flags["hardware_encoder_match"] and flags["timeline_consistent"] and flags["container_intact"] and flags["metadata_present"]:
            is_authentic = True
            verdict_label = "AUTHENTIC_CAMERA_CAPTURE"
            risk_level = "LOW"
            score = max(score, 0.90)
        elif not flags["metadata_present"] and not flags["hardware_encoder_match"]:
            is_authentic = None
            verdict_label = "UNVERIFIED_METADATA_STRIPPED"
            risk_level = "MEDIUM"
            caveats.append("Metadata was stripped (standard for social media / messaging platforms); authenticity cannot be mathematically proven.")
        elif not flags["timeline_consistent"]:
            is_authentic = False
            verdict_label = "MODIFIED_METADATA_INCONSISTENT"
            risk_level = "MEDIUM"
        else:
            is_authentic = None
            verdict_label = "INCONCLUSIVE_SIGNALS"

        # Forensic Caveats
        caveats.append("Authenticity verdicts are derived from structural, cryptographic, and heuristic signals.")
        caveats.append("Absence of metadata does not indicate malicious intent as platforms routinely transcode images.")

        return AuthenticityVerdict(
            is_authentic=is_authentic,
            verdict_label=verdict_label,
            confidence_score=round(score, 2),
            risk_level=risk_level,
            integrity_flags=flags,
            supporting_reasons=reasons,
            forensic_caveats=caveats,
        )
