"""Ollama Local Vision AI integration module for matazero."""

from imgint.core.ai.ollama import OllamaClient
from imgint.core.ai.analyzer import OllamaVisionAnalyzer
from imgint.core.ai.renderer import OllamaRenderer
from imgint.core.ai.prompts import (
    FORENSIC_EXAMINATION_PROMPT,
    QUICK_CAPTION_PROMPT,
    OCR_TRANSCRIPTION_PROMPT,
)

__all__ = [
    "OllamaClient",
    "OllamaVisionAnalyzer",
    "OllamaRenderer",
    "FORENSIC_EXAMINATION_PROMPT",
    "QUICK_CAPTION_PROMPT",
    "OCR_TRANSCRIPTION_PROMPT",
]
