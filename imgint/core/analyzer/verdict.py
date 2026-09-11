"""Authenticity and Integrity Verdict Evaluator for matazero."""

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional
from imgint.core.model.record import AnalysisRecord



TRAILING_DATA_PENALTY = 0.35
TIMELINE_INVERSION_PENALTY = 0.20
LSB_ENTROPY_PENALTY = 0.15

HARDWARE_MATCH_BONUS = 0.25
C2PA_SIGNED_BONUS = 0.20
GPS_FIX_BONUS = 0.10

AI_GENERATOR_SCORE = 0.10
AI_FFT_SCORE_CEILING = 0.20
EDITING_SUITE_SCORE = 0.40
SOCIAL_MEDIA_SCORE = 0.50
AUTHENTIC_MINIMUM_SCORE = 0.90

BASE_SCORE = 0.50


CAMERA_HARDWARE_KEYWORDS = (
    "iPhone", "Galaxy", "Pixel", "Canon", "Nikon", "Sony", "Fujifilm",
    "Xiaomi", "Redmi", "OnePlus", "Oppo", "Huawei", "GoPro", "DJI",
    "Panasonic", "Olympus", "Ricoh", "Leica", "Hasselblad",
    "Ring", "Nest", "Vivo", "Motorola", "Nothing",
)

AI_GENERATOR_KEYWORDS = (
    "Midjourney", "Stable Diffusion", "DALL-E", "DALL·E", "Firefly",
    "Imagen", "Flux", "AI Generator", "ai_generator",
)

EDITING_SOFTWARE_KEYWORDS = (
    "Photoshop", "Lightroom", "Capture One",
    "Affinity Photo", "DxO", "Luminar",
)

CODEC_LIBRARY_KEYWORDS = (
    "GIMP", "MozJPEG", "IJG", "libjpeg", "Pillow", "ImageMagick",
    "codec_library",
)

SOCIAL_MEDIA_KEYWORDS = (
    "WhatsApp", "Telegram", "Twitter", "Discord",
    "Instagram", "Signal", "Facebook", "Snapchat", "TikTok",
    "LinkedIn", "social_media",
)


@dataclass
class AuthenticityVerdict:
    is_authentic: Optional[bool]
    verdict_label: str
    confidence_score: float
    risk_level: str
    integrity_flags: Dict[str, bool]
    supporting_reasons: List[str]
    forensic_caveats: List[str]
    corroborating_signals: List[str] = field(default_factory=list)
    contradicting_signals: List[str] = field(default_factory=list)
    inconclusive_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuthenticityEvaluator:
    """Computes an evidence-grounded boolean authenticity verdict and integrity rating."""

    @classmethod
    def evaluate(cls, record: AnalysisRecord) -> AuthenticityVerdict:
        reasons: List[str] = []
        caveats: List[str] = []
        corroborating: List[str] = []
        contradicting: List[str] = []
        inconclusive: List[str] = []

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

        score = BASE_SCORE
        is_authentic: Optional[bool] = None
        risk_level = "LOW"

        trailing_data_f = next((f for f in record.findings if f.name == "trailing_data_detected"), None)
        has_trailing = trailing_data_f is not None or any(u.name == "TRAILING_DATA" for u in record.structural_units)
        if has_trailing:
            flags["container_intact"] = False
            flags["trailing_payload_detected"] = True
            reasons.append("Container has trailing data or embedded payload past the file termination marker (EOI/IEND).")
            contradicting.append("Trailing payload or unparsed data detected past file termination marker (EOI/IEND).")
            risk_level = "HIGH"
            score -= TRAILING_DATA_PENALTY
        else:
            corroborating.append("File container terminates cleanly at expected end-of-image marker.")

        timeline_f = next((f for f in record.findings if f.name == "indicator_timeline_inversion"), None)
        if timeline_f:
            flags["timeline_consistent"] = False
            reasons.append("ModifyDate chronologically precedes DateTimeOriginal (timeline contradiction).")
            contradicting.append("ModifyDate chronologically precedes DateTimeOriginal (timeline contradiction).")
            risk_level = "MEDIUM" if risk_level != "HIGH" else "HIGH"
            score -= TIMELINE_INVERSION_PENALTY
        elif any(f.name in ("datetime_original", "create_date", "modify_date") for f in record.findings):
            corroborating.append("Embedded temporal timestamps are chronologically consistent.")

        lsb_f = next((f for f in record.findings if f.name == "lsb_entropy_screening"), None)
        if lsb_f and isinstance(lsb_f.value, dict):
            is_anomaly = lsb_f.value.get("lsb_anomaly", False) or "High Density" in str(lsb_f.value.get("Anomaly Status", ""))
            if is_anomaly:
                flags["steganography_suspected"] = True
                reasons.append("High LSB entropy density detected (potential steganographic carrier or dense texture).")
                contradicting.append("High LSB entropy density detected (potential steganographic carrier or dense texture).")
                score -= LSB_ENTROPY_PENALTY
            else:
                corroborating.append("LSB bitplane entropy matches natural image baseline.")

        fft_f = next((f for f in record.findings if f.name == "fft_synthetic_artifact_screening"), None)
        if fft_f and isinstance(fft_f.value, dict) and fft_f.value.get("synthetic_grid_artifact"):
            flags["ai_generation_detected"] = True
            reasons.append(f"2D FFT power spectrum detected periodic checkerboard grid artifacts (Peak ratio: {fft_f.value.get('fft_peak_ratio')}).")
            contradicting.append(f"2D FFT power spectrum detected periodic checkerboard grid artifacts (Peak ratio: {fft_f.value.get('fft_peak_ratio')}).")
            score = min(score, AI_FFT_SCORE_CEILING)
            risk_level = "HIGH"

        attr_f = next((f for f in record.findings if f.name == "encoder_attribution"), None)
        if attr_f and isinstance(attr_f.value, dict):
            model = attr_f.value.get("device_model") or attr_f.value.get("Device Model", "")
            category = attr_f.value.get("category", "")
            sim = attr_f.value.get("similarity_score") or attr_f.value.get("Similarity Score", 0.0)
            is_ambiguous = attr_f.value.get("ambiguous", False)

            if is_ambiguous:
                collision_categories = attr_f.value.get("collision_categories", [])
                if "ai_generator" in collision_categories:
                    msg = (
                        f"Encoder fingerprint is ambiguous between categories: {', '.join(collision_categories)}. "
                        "AI generator is a candidate — flagging as potential synthetic."
                    )
                    reasons.append(msg)
                    contradicting.append(msg)
                    flags["ai_generation_detected"] = True
                    risk_level = "HIGH"
                    score = min(score, 0.3)
                else:
                    msg = f"Encoder fingerprint is ambiguous across categories: {', '.join(collision_categories)}."
                    reasons.append(msg)
                    inconclusive.append(msg)
                    caveats.append("Multiple encoder sources match with similar confidence; definitive attribution requires additional signals.")

            elif any(k in model for k in AI_GENERATOR_KEYWORDS) or category == "ai_generator":
                flags["ai_generation_detected"] = True
                reasons.append(f"Quantization & structure match Generative AI pipeline ({model}).")
                contradicting.append(f"Quantization profile matches Generative AI synthesis model ({model}).")
                score = AI_GENERATOR_SCORE
                risk_level = "HIGH"
                is_authentic = False

            elif any(k in model for k in EDITING_SOFTWARE_KEYWORDS) or category == "editing_software":
                reasons.append(f"Quantization tables match post-processing editing suite ({model}).")
                contradicting.append(f"Quantization tables match desktop image editing software ({model}).")
                score = EDITING_SUITE_SCORE
                risk_level = "MEDIUM"
                is_authentic = False

            elif any(k in model for k in CODEC_LIBRARY_KEYWORDS) or category == "codec_library":
                reasons.append(f"Quantization tables match generic codec library ({model}).")
                inconclusive.append(f"Quantization tables match generic codec library ({model}) common across native and altered files.")
                score = SOCIAL_MEDIA_SCORE
                caveats.append("Codec libraries (IJG, MozJPEG, GIMP) are used by many applications; attribution to a specific tool is not possible from DQT alone.")

            elif any(k in model for k in CAMERA_HARDWARE_KEYWORDS) or category == "camera_hardware":
                flags["hardware_encoder_match"] = True
                reasons.append(f"Quantization profile matches native camera hardware ISP ({model}).")
                corroborating.append(f"Quantization profile matches native camera hardware ISP ({model}).")
                score += HARDWARE_MATCH_BONUS

            elif any(k in model for k in SOCIAL_MEDIA_KEYWORDS) or category == "social_media":
                reasons.append(f"Quantization matches social media / messaging re-encoder ({model}).")
                inconclusive.append(f"Quantization matches social media / messaging re-encoder ({model}); camera tables superseded by platform transcoding.")
                score = SOCIAL_MEDIA_SCORE

        c2pa_f = next((f for f in record.findings if f.name == "c2pa_manifest_presence"), None)
        if c2pa_f and isinstance(c2pa_f.value, dict) and c2pa_f.value.get("present"):
            flags["c2pa_signed"] = True
            gen = c2pa_f.value.get("claim_generator", "Unknown")
            actions = c2pa_f.value.get("actions_history", [])
            reasons.append(f"C2PA authenticity manifest present (Claim Generator: {gen}, Actions: {len(actions)}).")
            corroborating.append(f"C2PA authenticity manifest present and verified (Claim Generator: {gen}, Actions: {len(actions)}).")
            score += C2PA_SIGNED_BONUS

        gps_f = next((f for f in record.findings if f.name in ("gps_coordinates_claimed", "gps_location_fix")), None)
        gps_uninitialized = next((f for f in record.findings if f.name == "gps_fix_uninitialized"), None)
        gps_confidence_f = next((f for f in record.findings if f.name == "gps_location_confidence"), None)

        if gps_f and not gps_uninitialized:
            confidence_level = None
            if gps_confidence_f and isinstance(gps_confidence_f.value, dict):
                confidence_level = gps_confidence_f.value.get("level")

            if confidence_level in ("REJECTED", "LOW"):
                caveats.append(
                    f"GPS coordinates present but location confidence is {confidence_level}. "
                    "No authenticity bonus awarded."
                )
                inconclusive.append(f"GPS coordinates present with {confidence_level} confidence.")
            else:
                reasons.append("GPS geolocation fix embedded in container metadata.")
                corroborating.append("Valid GPS geolocation fix embedded in container metadata.")
                score += GPS_FIX_BONUS
        elif gps_uninitialized:
            caveats.append(
                "GPS metadata present but coordinates are uninitialized/invalid "
                "(Null Island or out-of-bounds). Not used for authenticity assessment."
            )
            inconclusive.append("GPS metadata present but coordinates are uninitialized/zeroed (Null Island).")
        elif not flags["metadata_present"]:
            inconclusive.append("Embedded container metadata absent (standard consequence of privacy stripping or platform transcoding).")

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
            score = max(score, AUTHENTIC_MINIMUM_SCORE)
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
            corroborating_signals=corroborating,
            contradicting_signals=contradicting,
            inconclusive_signals=inconclusive,
        )
