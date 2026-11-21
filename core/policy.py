"""Deterministic Security Policy Engine for VibeArmor Commit, PR, and Deployment Gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import yaml
from pydantic import BaseModel

from core.models import Finding, PatchReport, Pillar, RemediationStatus, ScanAndHealReport, Severity

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "security_policy.yaml"


class SecurityPolicyConfig(BaseModel):
    block_critical: bool = True
    block_high: bool = True
    block_medium: bool = False
    require_verification: bool = True
    require_tests: bool = True
    allow_unverified_ai_patch: bool = False
    secrets_block_commit: bool = True


def load_security_policy(policy_path: Path | None = None) -> SecurityPolicyConfig:
    target = policy_path or DEFAULT_POLICY_PATH
    if not target.exists():
        cfg = SecurityPolicyConfig()
        save_security_policy(cfg, target)
        return cfg
    try:
        raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        sec = raw.get("security", raw) if isinstance(raw, dict) else {}
        return SecurityPolicyConfig(**{k: v for k, v in sec.items() if k in SecurityPolicyConfig.model_fields})
    except Exception:
        return SecurityPolicyConfig()


def save_security_policy(cfg: SecurityPolicyConfig, policy_path: Path | None = None) -> Path:
    target = policy_path or DEFAULT_POLICY_PATH
    payload = {"security": cfg.model_dump()}
    target.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return target


def evaluate_policy(
    report: ScanAndHealReport,
    policy: SecurityPolicyConfig | None = None,
) -> Dict[str, Any]:
    """Deterministically evaluate whether a workspace/commit/PR passes organizational security policy.

    The AI model NEVER controls this decision.
    """
    cfg = policy or load_security_policy()
    active_findings: List[Finding] = (
        [f for f in report.findings_after if f.reachable and not f.requires_policy_spec]
        if report.mode == "auto_heal"
        else [f for f in report.findings_before if f.reachable and not f.requires_policy_spec]
    )

    violations: List[str] = []
    crit_open = [f for f in active_findings if f.severity == Severity.CRITICAL]
    high_open = [f for f in active_findings if f.severity == Severity.HIGH]
    med_open = [f for f in active_findings if f.severity == Severity.MEDIUM]
    sec_open = [f for f in active_findings if f.pillar == Pillar.SECRET_BOUNDARY]

    if cfg.secrets_block_commit and sec_open:
        violations.append(
            f"secrets_block_commit: {len(sec_open)} secret/credential exposure(s) remain open."
        )
    if cfg.block_critical and crit_open:
        violations.append(
            f"block_critical: {len(crit_open)} CRITICAL vulnerability(ies) remain open."
        )
    if cfg.block_high and high_open:
        violations.append(
            f"block_high: {len(high_open)} HIGH vulnerability(ies) remain open."
        )
    if cfg.block_medium and med_open:
        violations.append(
            f"block_medium: {len(med_open)} MEDIUM vulnerability(ies) remain open."
        )

    unverified_patches: List[PatchReport] = []
    failed_test_gates: List[str] = []
    for p in report.patches:
        if p.status in {RemediationStatus.ABSTAINED, RemediationStatus.INFO_ONLY}:
            continue
        if cfg.require_verification and p.status != RemediationStatus.FIXED_VERIFIED:
            unverified_patches.append(p)
        if cfg.require_tests and p.edits:
            g1_ok = any(g.passed and ("Gate 1" in g.gate_name or "Compile" in g.gate_name) for g in p.gates)
            if not g1_ok:
                failed_test_gates.append(p.rule_id)

    if cfg.require_verification and unverified_patches:
        violations.append(
            f"require_verification: {len(unverified_patches)} patch(es) failed independent verification."
        )
    if cfg.require_tests and failed_test_gates:
        violations.append(
            f"require_tests: Gate 1 compile/test verification failed on {', '.join(failed_test_gates)}."
        )

    passed = len(violations) == 0
    return {
        "verdict": "PASS" if passed else "BLOCK",
        "passed": passed,
        "policy": cfg.model_dump(),
        "violations": violations,
        "counts": {
            "critical_open": len(crit_open),
            "high_open": len(high_open),
            "medium_open": len(med_open),
            "secrets_open": len(sec_open),
            "verified_patches": sum(1 for p in report.patches if p.status == RemediationStatus.FIXED_VERIFIED),
            "rejected_patches": sum(
                1 for p in report.patches if p.status in {RemediationStatus.ROLLBACK_ON_GATE_FAIL, RemediationStatus.UNPATCHED}
            ),
        },
    }
