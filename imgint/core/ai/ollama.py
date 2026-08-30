"""Ollama local vision model client using standard library HTTP."""

from __future__ import annotations
import base64
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


KNOWN_VISION_MODELS = (
    "llava",
    "moondream",
    "llama3.2-vision",
    "minicpm-v",
    "qwen2-vl",
    "qwen2.5-vl",
    "bakllava",
    "vision",
)


class OllamaClient:
    """Zero-dependency local HTTP client for communicating with Ollama on localhost."""

    def __init__(self, host: str = "http://localhost:11434", timeout: int = 120) -> None:
        self.host = host.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        """Checks if the local Ollama daemon is running."""
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def list_models(self) -> List[Dict[str, Any]]:
        """Retrieves list of all locally installed models from Ollama."""
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("models", [])
        except Exception:
            return []

    def list_vision_models(self) -> List[str]:
        """Filters installed models for vision-capable models."""
        models = self.list_models()
        vision_models = []
        for m in models:
            name = m.get("name", "").lower()
            if any(vk in name for vk in KNOWN_VISION_MODELS):
                vision_models.append(m.get("name"))
        return vision_models

    def get_default_vision_model(self) -> Optional[str]:
        """Returns the first available local vision model or None."""
        v_models = self.list_vision_models()
        if v_models:
            return v_models[0]
        # Fallback to any model if tags exist
        all_models = self.list_models()
        if all_models:
            return all_models[0].get("name")
        return "llama3.2-vision"

    def generate(
        self,
        model: str,
        prompt: str,
        image_path_or_bytes: Optional[str | Path | bytes] = None,
        json_format: bool = False,
    ) -> Dict[str, Any]:
        """Sends an inference request to Ollama with optional image payload."""
        images_b64: List[str] = []

        if image_path_or_bytes is not None:
            if isinstance(image_path_or_bytes, (str, Path)):
                raw_img = Path(image_path_or_bytes).read_bytes()
            else:
                raw_img = image_path_or_bytes
            b64_str = base64.b64encode(raw_img).decode("ascii")
            images_b64.append(b64_str)

        payload: Dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if images_b64:
            payload["images"] = images_b64
        if json_format:
            payload["format"] = "json"

        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                return res_json
        except urllib.error.URLError as e:
            return {
                "error": f"Failed to communicate with Ollama at {self.host}: {e}. Ensure 'ollama serve' is running.",
                "response": "",
                "done": False,
            }
        except Exception as e:
            return {
                "error": str(e),
                "response": "",
                "done": False,
            }
