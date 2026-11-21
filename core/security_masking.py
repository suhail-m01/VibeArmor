"""Deterministic secret masking utility — prevents full credentials from appearing in UI, logs, or Evidence Packages."""

from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}\b"), r"\1************"),
    (re.compile(r"\b(sk-[A-Za-z0-9]{4})[A-Za-z0-9_\-]{12,}\b"), r"\1************"),
    (re.compile(r"\b(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{14,}\b"), r"\1************"),
    (re.compile(r"\b(github_pat_[A-Za-z0-9_]{6})[A-Za-z0-9_]{14,}\b"), r"\1************"),
    (re.compile(r"\b(AIza[0-9A-Za-z_\-]{4})[0-9A-Za-z_\-]{14,}\b"), r"\1************"),
    (re.compile(r"\b(rzp_(?:live|test)_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}\b"), r"\1************"),
    (re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8})\.[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{10,}\b"), r"\1.****.****"),
    (re.compile(r"(postgres(?:ql)?://[^:\s]+:)([^@\s]{4,})(@)"), r"\1********\3"),
]


def mask_secrets(text: str | None) -> str:
    """Mask known API keys, PATs, JWTs, and DB credentials while preserving prefix context."""
    if not text:
        return ""
    out = str(text)
    for rx, repl in _PATTERNS:
        out = rx.sub(repl, out)
    return out


def mask_token_preview(token: str | None) -> str:
    """Return a safe masked preview for a configured PAT (e.g. 'ghp_abcd************9x')."""
    if not token:
        return ""
    t = token.strip()
    if len(t) <= 10:
        return "********"
    return f"{t[:8]}************{t[-2:]}"
