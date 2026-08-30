"""Ollama Vision Analyzer for Tier 7 Pipeline Integration."""

from __future__ import annotations
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from imgint.core.ai.ollama import OllamaClient
from imgint.core.ai.prompts import FORENSIC_EXAMINATION_PROMPT
from imgint.core.analyzer.base import AnalysisContext
from imgint.core.model.finding import Finding, Confidence, Provenance
from imgint.core.model.record import Diagnostic


class OllamaVisionAnalyzer:
    """Runs local Ollama vision inspection and generates structured Tier 7 findings."""

    @classmethod
    def analyze(
        cls, ctx: AnalysisContext, model_name: Optional[str] = None
    ) -> Tuple[List[Finding], List[Diagnostic]]:
        """
        Run local Ollama vision inspection and generate structured Tier 7 findings.

        Args:
            ctx: The analysis context containing the image and metadata.
            model_name: Optional specific vision model name to use.
            
        Returns:
            A tuple of (findings, diagnostics).
        """
        findings: List[Finding] = []
        diagnostics: List[Diagnostic] = []

        client = OllamaClient()
        if not client.is_available():
            diagnostics.append(
                Diagnostic(
                    level="warning",
                    message="Ollama local service is not responding at http://localhost:11434. Skipping AI vision analysis.",
                    source="ollama_vision_analyzer",
                )
            )
            return findings, diagnostics

        selected_model = model_name or client.get_default_vision_model()
        if not selected_model:
            diagnostics.append(
                Diagnostic(
                    level="warning",
                    message="No vision-capable model found in local Ollama. Install one with 'ollama pull llama3.2-vision' or 'ollama pull moondream'.",
                    source="ollama_vision_analyzer",
                )
            )
            return findings, diagnostics

        raw_bytes = ctx.reader.get_all_bytes()
        res = client.generate(
            model=selected_model,
            prompt=FORENSIC_EXAMINATION_PROMPT,
            image_path_or_bytes=raw_bytes,
            json_format=True,
        )

        if res.get("error"):
            diagnostics.append(
                Diagnostic(
                    level="warning",
                    message=f"Ollama inference error: {res['error']}",
                    source="ollama_vision_analyzer",
                )
            )
            return findings, diagnostics

        response_text = res.get("response", "").strip()
        
        # Strip markdown code fences if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        elif response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        try:
            parsed_data = json.loads(response_text)
        except Exception:
            # Fallback JSON extraction
            match = re.search(r'(\{.*\})', response_text, re.DOTALL)
            if match:
                try:
                    parsed_data = json.loads(match.group(1))
                except Exception:
                    parsed_data = {"raw_response": response_text}
            else:
                parsed_data = {"raw_response": response_text}

        findings.append(
            Finding(
                name="ollama_visual_forensic_examination",
                value={
                    "model_used": selected_model,
                    "examination_results": parsed_data,
                },
                tier=7,
                extractor="ollama_vision_analyzer",
                confidence=Confidence.DERIVED,
                caveat="Local Vision LLM heuristic assessment. Subject to model capability and visual resolution.",
                provenance=Provenance(
                    source_layer="ai_vision",
                    extractor=f"ollama_{selected_model}",
                ),
            )
        )

        return findings, diagnostics
