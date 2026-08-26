"""Report signing and signature verification per SRD FR-9.6."""

from __future__ import annotations
import hashlib
import hmac
import json
from typing import Any, Dict, Optional


class ReportSigner:
    """Signs reports using HMAC-SHA256 or detached SHA-256 digests."""

    @staticmethod
    def sign_report(report_json: str, secret_key: str) -> str:
        return hmac.new(secret_key.encode("utf-8"), report_json.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def verify_signature(report_json: str, signature: str, secret_key: str) -> bool:
        expected = ReportSigner.sign_report(report_json, secret_key)
        return hmac.compare_digest(expected, signature)
