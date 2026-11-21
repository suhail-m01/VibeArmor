"""Tier-2 Local Open-Weight SLM Engine (`Qwen2.5-Coder`) over Minimal Security Slices (MSS).

Supports:
  1. Ollama HTTP (`OLLAMA_HOST`, default `http://127.0.0.1:11434`, `qwen2.5-coder:3b` / `1.5b`)
  2. Embedded `llama-cpp-python` GGUF (`qwen2.5-coder-0.5b-instruct-q4_k_m.gguf` / `1.5b`)
     running 100% locally offline on CPU/GPU with zero cloud API calls!
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx

from core.models import Finding, MinimalSecuritySlice

_LLAMA_INSTANCE: Any = None
_ACTIVE_BACKEND_NAME: str = "uninitialized"
_OLLAMA_AVAILABLE: Optional[bool] = None

GGUF_SEARCH_PATHS = [
    Path(os.environ.get("VIBEARMOR_GGUF_PATH", "/nonexistent")),
    Path.home() / ".cache/vibearmor/models/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
    Path.home() / ".cache/vibearmor/models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf",
    Path("/home/user/.cache/vibearmor/models/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf"),
    Path("/home/user/.cache/vibearmor/models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf"),
]


def _get_llama_cpp_model() -> Optional[Any]:
    global _LLAMA_INSTANCE, _ACTIVE_BACKEND_NAME
    if _LLAMA_INSTANCE is not None:
        return _LLAMA_INSTANCE
    try:
        from llama_cpp import Llama  # type: ignore

        for p in GGUF_SEARCH_PATHS:
            if p.exists():
                _LLAMA_INSTANCE = Llama(
                    model_path=str(p),
                    n_ctx=2048,
                    n_threads=max(2, os.cpu_count() or 2),
                    verbose=False,
                )
                _ACTIVE_BACKEND_NAME = f"llama.cpp:{p.name}"
                return _LLAMA_INSTANCE
    except Exception:
        return None
    return None


def _try_ollama(prompt: str, max_tokens: int = 240) -> Optional[Tuple[str, str]]:
    global _OLLAMA_AVAILABLE
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    if _OLLAMA_AVAILABLE is False:
        return None
    model = os.environ.get("VIBEARMOR_OLLAMA_MODEL", "qwen2.5-coder:3b")
    try:
        resp = httpx.post(
            f"{host}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.05, "num_predict": max_tokens},
            },
            timeout=1.2,
        )
        if resp.status_code == 200:
            _OLLAMA_AVAILABLE = True
            return resp.json().get("response", ""), f"ollama:{model}"
        _OLLAMA_AVAILABLE = False
    except Exception:
        _OLLAMA_AVAILABLE = False
    return None


def _extract_code_or_json(raw_text: str) -> str:
    text = raw_text.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            for key in ("patched_code", "sql", "code", "fix"):
                if key in parsed and isinstance(parsed[key], str):
                    return parsed[key].strip()
    except Exception:
        pass

    m_fence = re.search(r"```(?:python|sql|typescript|tsx|js|json)?\s*\n(.+?)```", text, re.DOTALL | re.IGNORECASE)
    if m_fence:
        inner = m_fence.group(1).strip()
        try:
            parsed2 = json.loads(inner)
            if isinstance(parsed2, dict) and "patched_code" in parsed2:
                return str(parsed2["patched_code"]).strip()
        except Exception:
            return inner
    return text


def repair_slice_with_slm(
    finding: Finding,
    mss: MinimalSecuritySlice,
    full_file_content: str,
    compiler_feedback: str = "",
) -> Tuple[Optional[str], str, float]:
    """Run local open-weight Qwen2.5-Coder on the ~25-line Minimal Security Slice (MSS).

    Returns: (patched_full_file_or_sql, backend_label, latency_ms)
    """
    t0 = time.perf_counter()

    if finding.pillar.value == "rls_dpdp" and finding.file_path.endswith(".sql"):
        tname = finding.metadata.get("table", "items")
        fks = finding.metadata.get("foreign_keys", {})
        fk_hint = ""
        for c_col, pair in fks.items():
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                fk_hint = f"EXISTS (SELECT 1 FROM public.{pair[0]} p WHERE p.{pair[1]} = {tname}.{c_col} AND p.user_id = (select auth.uid()))"
        sys_msg = (
            "You are VibeArmor SQL Security Synthesizer. Return JSON {\"patched_code\": \"...\"} with valid PostgreSQL "
            "enabling RLS and creating a policy on public." + tname + " FOR ALL TO authenticated USING (...) WITH CHECK (...)."
        )
        user_msg = (
            f"{mss.cross_layer_context}\n"
            f"Table slice:\n{mss.primary_slice}\n"
            f"{('Required FK predicate: ' + fk_hint) if fk_hint else ''}\n"
            f"{('Compiler feedback: ' + compiler_feedback) if compiler_feedback else ''}\n"
            f'Return JSON: {{"patched_code": "ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY; CREATE POLICY \\"{tname}_fk_owner\\" ON public.{tname} FOR ALL TO authenticated USING (...);"}}'
        )
    else:
        sys_msg = (
            "You are VibeArmor Security Patcher. Fix ONLY the security vulnerability in the code slice "
            "(use parameterized SQL ?, subprocess shell=False, ast.literal_eval, yaml.safe_load, os.path.basename, or hmac.compare_digest). "
            "Preserve exact function names and return JSON: {\"patched_code\": \"...\"}"
        )
        user_msg = (
            f"Vulnerability: {finding.title} ({finding.cwe})\n"
            f"Code slice:\n{mss.primary_slice}\n"
            f"{('Compiler feedback: ' + compiler_feedback) if compiler_feedback else ''}\n"
            'Respond strictly with JSON: {"patched_code": "<fixed code slice>"}'
        )

    # 1. Try Ollama first (for laptop GPU deployment)
    ollama_res = _try_ollama(f"{sys_msg}\n\n{user_msg}")
    raw_reply = None
    backend_used = "unavailable"

    if ollama_res is not None:
        raw_reply, backend_used = ollama_res
    else:
        # 2. Run embedded local GGUF model via llama-cpp-python!
        llm = _get_llama_cpp_model()
        if llm is not None:
            chat_out: Dict[str, Any] = llm.create_chat_completion(
                messages=[
                    {"role": "system", "content": sys_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.02,
                max_tokens=190,
                response_format={"type": "json_object"},
            )
            raw_reply = chat_out["choices"][0]["message"]["content"]
            backend_used = _ACTIVE_BACKEND_NAME

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    if not raw_reply:
        return None, backend_used, elapsed_ms

    patched_slice = _extract_code_or_json(raw_reply)
    if not patched_slice:
        return None, backend_used, elapsed_ms

    # For SQL RLS, return the synthesized policy SQL directly
    if finding.pillar.value == "rls_dpdp" and finding.file_path.endswith(".sql"):
        return patched_slice, backend_used, elapsed_ms

    # Splice the repaired slice cleanly back into full_file_content
    if mss.primary_slice in full_file_content:
        merged = full_file_content.replace(mss.primary_slice, patched_slice, 1)
    else:
        merged = patched_slice

    return merged, backend_used, elapsed_ms


def zero_shot_full_file_rewrite(file_path: str, full_content: str) -> Tuple[Optional[str], str, float]:
    """Baseline 2 for Track 03 Benchmark: Raw Zero-Shot Full-File SLM Rewrite (NO Symbolic Slicing, NO Cross-Layer Graph)."""
    t0 = time.perf_counter()
    prompt = (
        f"Find and fix any security vulnerabilities in `{file_path}`. "
        "Return JSON {\"patched_code\": \"<entire rewritten file>\"}.\n\n"
        f"{full_content[:3600]}"
    )

    ollama_res = _try_ollama(prompt, max_tokens=700)
    if ollama_res is not None:
        raw_reply, backend = ollama_res
    else:
        llm = _get_llama_cpp_model()
        if llm is None:
            return None, "unavailable", round((time.perf_counter() - t0) * 1000.0, 2)
        out: Dict[str, Any] = llm.create_chat_completion(
            messages=[
                {"role": "system", "content": "Rewrite the entire file fixing security bugs. Output JSON: {\"patched_code\": \"...\"}."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=260,
            response_format={"type": "json_object"},
        )
        raw_reply = out["choices"][0]["message"]["content"]
        backend = _ACTIVE_BACKEND_NAME

    elapsed = round((time.perf_counter() - t0) * 1000.0, 2)
    code = _extract_code_or_json(raw_reply or "")
    return (code if code else None), backend, elapsed


def get_slm_status() -> Dict[str, Any]:
    gguf_found = next((str(p) for p in GGUF_SEARCH_PATHS if p.exists()), None)
    ollama_host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    ollama_online = False
    try:
        r = httpx.get(f"{ollama_host}/api/tags", timeout=0.6)
        ollama_online = r.status_code == 200
    except Exception:
        ollama_online = False
    return {
        "active_backend": _ACTIVE_BACKEND_NAME if _ACTIVE_BACKEND_NAME != "uninitialized" else ("ollama" if ollama_online else ("llama.cpp" if gguf_found else "deterministic_only")),
        "gguf_model_cached": bool(gguf_found),
        "gguf_path": gguf_found,
        "ollama_online": ollama_online,
    }

