"""Extensible ModelProvider abstraction separating Probabilistic AI Patch Proposal from Deterministic Security Decisions."""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
from typing import Any, Dict, List, Optional
import httpx

from core.remediators.slm_mss import get_slm_status, repair_slice_with_slm


class ModelProvider(ABC):
    """Abstract interface for code remediation models (Qwen GGUF, OpenAI-compatible, or Symbolic)."""

    provider_id: str = "base"
    display_name: str = "Base Provider"

    @abstractmethod
    def is_available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def propose_slice_remediation(
        self,
        primary_slice: str,
        evidence_context: str,
        rule_id: str,
        cwe: str,
    ) -> Dict[str, Any]:
        """Propose a minimal patch candidate. Never determines security verification status."""
        raise NotImplementedError


class QwenLocalModelProvider(ModelProvider):
    provider_id = "qwen_local"
    display_name = "Qwen2.5-Coder (Local GGUF / Ollama)"

    def is_available(self) -> bool:
        st = get_slm_status()
        return bool(st.get("gguf_available") or st.get("ollama_available"))

    def status_metadata(self) -> Dict[str, Any]:
        return get_slm_status()

    def propose_slice_remediation(
        self,
        primary_slice: str,
        evidence_context: str,
        rule_id: str,
        cwe: str,
    ) -> Dict[str, Any]:
        patched_text, backend_lbl = repair_slice_with_slm(
            primary_slice=primary_slice,
            cross_layer_context=evidence_context,
            rule_id=rule_id,
            cwe=cwe,
        )
        return {
            "provider": self.provider_id,
            "backend": backend_lbl,
            "proposed_code": patched_text,
            "status": "PROPOSED_UNVERIFIED" if patched_text else "UNAVAILABLE",
        }


class OpenAICompatibleModelProvider(ModelProvider):
    """Server-side OpenAI-compatible provider (e.g. vLLM, Together, Groq, OpenAI). API keys stay strictly server-side."""

    provider_id = "openai_compatible"
    display_name = "OpenAI-Compatible Endpoint (Server-Side)"

    def __init__(self) -> None:
        self.api_base = os.getenv("VIBEARMOR_LLM_API_BASE", "").rstrip("/")
        self.api_key = os.getenv("VIBEARMOR_LLM_API_KEY", "")
        self.model = os.getenv("VIBEARMOR_LLM_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct")

    def is_available(self) -> bool:
        return bool(self.api_base and self.api_key)

    def propose_slice_remediation(
        self,
        primary_slice: str,
        evidence_context: str,
        rule_id: str,
        cwe: str,
    ) -> Dict[str, Any]:
        if not self.is_available():
            return {"provider": self.provider_id, "backend": "not_configured", "proposed_code": None, "status": "UNAVAILABLE"}
        prompt = (
            f"Remediate {rule_id} ({cwe}) with the minimal possible code modification.\n"
            f"Grounded Security Evidence:\n{evidence_context}\n\n"
            f"Vulnerable Slice:\n```\n{primary_slice}\n```\n"
            "Return ONLY the corrected code slice with no markdown fences."
        )
        try:
            with httpx.Client(timeout=15.0) as client:
                r = client.post(
                    f"{self.api_base}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={
                        "model": self.model,
                        "temperature": 0.0,
                        "messages": [
                            {"role": "system", "content": "You generate minimal security patches grounded in CWE/OWASP evidence."},
                            {"role": "user", "content": prompt},
                        ],
                    },
                )
                if r.status_code >= 400:
                    return {"provider": self.provider_id, "backend": "http_error", "proposed_code": None, "status": "ERROR"}
                content = r.json()["choices"][0]["message"]["content"].strip()
                return {
                    "provider": self.provider_id,
                    "backend": self.model,
                    "proposed_code": content,
                    "status": "PROPOSED_UNVERIFIED",
                }
        except Exception as exc:
            return {"provider": self.provider_id, "backend": str(exc), "proposed_code": None, "status": "ERROR"}


class DeterministicSymbolicProvider(ModelProvider):
    provider_id = "deterministic_ast_codemod"
    display_name = "Deterministic AST & SQL Symbolic Codemod"

    def is_available(self) -> bool:
        return True

    def propose_slice_remediation(
        self,
        primary_slice: str,
        evidence_context: str,
        rule_id: str,
        cwe: str,
    ) -> Dict[str, Any]:
        return {
            "provider": self.provider_id,
            "backend": "ast_sqlglot_codemod",
            "proposed_code": primary_slice,
            "status": "PROPOSED_UNVERIFIED",
        }


def list_model_providers() -> List[Dict[str, Any]]:
    providers: List[ModelProvider] = [
        QwenLocalModelProvider(),
        OpenAICompatibleModelProvider(),
        DeterministicSymbolicProvider(),
    ]
    return [
        {
            "provider_id": p.provider_id,
            "display_name": p.display_name,
            "available": p.is_available(),
        }
        for p in providers
    ]
