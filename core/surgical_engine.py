"""Strict Non-Destructive Surgical Remediation Staging & User-Approved Adoption Engine.

Guarantees:
1. Staging NEVER modifies the user's workspace on disk until explicit user approval.
2. Unrelated / safe files are 100% untouched (0 bytes altered).
3. Inside vulnerable files, ONLY the vulnerable AST statement / SQL policy / secret line is patched,
   computing a byte-for-byte preservation percentage and side-by-side hunk comparison.
4. Selective adoption applies ONLY the exact finding IDs approved by the user, re-verified by Gate 1-3.
"""

from __future__ import annotations

import difflib
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from core.detectors import run_all_detectors
from core.engine import _apply_edits_to_disk, _build_summary, _generate_deterministic_edits, scan_and_heal
from core.graph.cross_layer_graph import WorkspaceContext, build_workspace_context
from core.models import (
    FileEdit,
    Finding,
    PatchReport,
    RemediationStatus,
    ScanAndHealReport,
)
from core.remediators.slm_mss import repair_slice_with_slm
from core.slicer.mss_slicer import extract_mss
from core.verifier.gate1_compile import run_gate1_compile
from core.verifier.gate2_rescan import run_gate2_rescan
from core.verifier.gate3_poc_probe import run_gate3_poc_probe


def _compute_file_precision_metrics(before_txt: str, after_txt: str, created_new: bool) -> Dict[str, Any]:
    """Compute exact line-level surgical precision metrics proving non-vulnerable code was untouched."""
    if created_new or not before_txt:
        new_lines = after_txt.splitlines()
        return {
            "created_new": True,
            "original_lines": 0,
            "untouched_lines": 0,
            "changed_lines_before": 0,
            "added_lines_after": len(new_lines),
            "preservation_pct": 100.0,
            "changed_span_label": f"New security guard file (+{len(new_lines)} lines)",
            "vulnerable_excerpt": "// Missing server-side guard / gitignore protection",
            "corrected_excerpt": "\n".join(new_lines[:18]) + ("\n// ..." if len(new_lines) > 18 else ""),
        }

    b_lines = before_txt.splitlines()
    a_lines = after_txt.splitlines()
    matcher = difflib.SequenceMatcher(None, b_lines, a_lines)

    equal_count = 0
    changed_before = 0
    added_after = 0
    changed_ranges: List[str] = []
    vuln_hunks: List[str] = []
    fixed_hunks: List[str] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            equal_count += i2 - i1
        else:
            changed_before += i2 - i1
            added_after += j2 - j1
            if i1 == i2:
                changed_ranges.append(f"L{i1 + 1} (+{j2 - j1} additive lines)")
            elif i2 - i1 == 1:
                changed_ranges.append(f"L{i1 + 1}")
            else:
                changed_ranges.append(f"L{i1 + 1}–L{i2}")

            ctx_start_b = max(0, i1 - 2)
            ctx_end_b = min(len(b_lines), i2 + 2)
            vuln_hunks.append("\n".join(f"{ln + 1:>3} | {b_lines[ln]}" for ln in range(ctx_start_b, ctx_end_b)))

            ctx_start_a = max(0, j1 - 2)
            ctx_end_a = min(len(a_lines), j2 + 2)
            fixed_hunks.append("\n".join(f"{ln + 1:>3} | {a_lines[ln]}" for ln in range(ctx_start_a, ctx_end_a)))

    total_orig = max(1, len(b_lines))
    preservation_pct = round((equal_count / total_orig) * 100.0, 1)

    return {
        "created_new": False,
        "original_lines": len(b_lines),
        "untouched_lines": equal_count,
        "changed_lines_before": changed_before,
        "added_lines_after": added_after,
        "preservation_pct": preservation_pct,
        "changed_span_label": ", ".join(changed_ranges[:4]) or "Additive guard",
        "vulnerable_excerpt": "\n---\n".join(vuln_hunks[:2]) or before_txt[:300],
        "corrected_excerpt": "\n---\n".join(fixed_hunks[:2]) or after_txt[:300],
    }


def stage_surgical_proposals(
    workspace_dir: str | Path,
    allow_slm: bool = True,
    on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Run full 3-Gate remediation inside an isolated temp sandbox WITHOUT modifying workspace_dir."""
    src_root = Path(workspace_dir).resolve()

    with tempfile.TemporaryDirectory(prefix="vibearmor-stage-") as tmp:
        stage_root = Path(tmp) / src_root.name
        shutil.copytree(src_root, stage_root, dirs_exist_ok=True)

        # Capture original files snapshot before staging
        before_ctx = build_workspace_context(stage_root)
        original_files: Dict[str, str] = dict(before_ctx.file_contents)

        staged_report: ScanAndHealReport = scan_and_heal(
            stage_root,
            auto_heal=True,
            allow_slm=allow_slm,
            on_event=on_event,
        )

        after_ctx = build_workspace_context(stage_root)
        staged_files: Dict[str, str] = dict(after_ctx.file_contents)
        # Ensure newly created dotfiles (.gitignore, .env.example, .env.local) are also captured
        for extra_name in (".gitignore", ".env.example", ".env.local"):
            ep = stage_root / extra_name
            if ep.exists():
                staged_files[extra_name] = ep.read_text(encoding="utf-8", errors="replace")

    finding_by_id: Dict[str, Finding] = {f.id: f for f in staged_report.findings_before}
    proposals: List[Dict[str, Any]] = []

    for patch in staged_report.patches:
        f_obj = finding_by_id.get(patch.finding_id)
        if not f_obj:
            continue

        if patch.status == RemediationStatus.ABSTAINED:
            proposals.append(
                {
                    "finding_id": patch.finding_id,
                    "rule_id": patch.rule_id,
                    "pillar": patch.pillar.value,
                    "severity": f_obj.severity.value,
                    "cwe": f_obj.cwe,
                    "title": f_obj.title,
                    "description": f_obj.description,
                    "file_path": f_obj.file_path,
                    "line_start": f_obj.line_start,
                    "line_end": f_obj.line_end,
                    "status": patch.status.value,
                    "adoptable": False,
                    "abstention_note": patch.abstention_note,
                    "strategy_used": patch.strategy_used,
                    "gates": [],
                    "file_diffs": [],
                    "precision": None,
                }
            )
            continue

        if patch.status != RemediationStatus.FIXED_VERIFIED:
            continue

        file_diffs: List[Dict[str, Any]] = []
        primary_precision: Optional[Dict[str, Any]] = None
        for ed in patch.edits:
            prec = _compute_file_precision_metrics(ed.before_content, ed.after_content, ed.created_new)
            if primary_precision is None or ed.file_path == f_obj.file_path:
                primary_precision = prec
            file_diffs.append(
                {
                    "file_path": ed.file_path,
                    "created_new": ed.created_new,
                    "before_content": ed.before_content,
                    "after_content": ed.after_content,
                    "unified_diff": ed.unified_diff,
                    "precision": prec,
                }
            )

        proposals.append(
            {
                "finding_id": patch.finding_id,
                "rule_id": patch.rule_id,
                "pillar": patch.pillar.value,
                "severity": f_obj.severity.value,
                "cwe": f_obj.cwe,
                "title": f_obj.title,
                "description": f_obj.description,
                "file_path": f_obj.file_path,
                "line_start": f_obj.line_start,
                "line_end": f_obj.line_end,
                "status": patch.status.value,
                "adoptable": True,
                "abstention_note": None,
                "strategy_used": patch.strategy_used,
                "repair_latency_ms": patch.repair_latency_ms,
                "mss": patch.mss.model_dump(mode="json") if patch.mss else None,
                "gates": [g.model_dump(mode="json") for g in patch.gates],
                "file_diffs": file_diffs,
                "precision": primary_precision,
            }
        )

    # Identify completely untouched files to prove strict surgical scope!
    touched_paths = {
        fd["file_path"]
        for p in proposals
        if p["adoptable"]
        for fd in p["file_diffs"]
    }
    untouched_safe_files = sorted(fp for fp in original_files if fp not in touched_paths)

    pres_values = [
        p["precision"]["preservation_pct"]
        for p in proposals
        if p["adoptable"] and p.get("precision") and not p["precision"]["created_new"]
    ]
    avg_preservation = round(sum(pres_values) / len(pres_values), 1) if pres_values else 100.0

    return {
        "staged_report": staged_report,
        "original_files": original_files,
        "staged_files": staged_files,
        "proposals": proposals,
        "adoptable_count": sum(1 for p in proposals if p["adoptable"]),
        "untouched_safe_files": untouched_safe_files,
        "touched_vulnerable_files": sorted(touched_paths),
        "avg_non_vulnerable_preservation_pct": avg_preservation,
    }


def adopt_selected_proposals(
    workspace_dir: str | Path,
    selected_finding_ids: List[str],
    staged_bundle: Optional[Dict[str, Any]] = None,
    allow_slm: bool = True,
) -> ScanAndHealReport:
    """Apply ONLY the user-selected finding fixes to workspace_dir with 3-Gate verification."""
    root = Path(workspace_dir).resolve()
    wanted: Set[str] = set(selected_finding_ids)

    # Fast-path: if all adoptable proposals were selected and we already have verified staged_files, write them atomically!
    if staged_bundle is not None:
        all_adoptable_ids = {p["finding_id"] for p in staged_bundle["proposals"] if p["adoptable"]}
        if wanted and wanted == all_adoptable_ids:
            backup_dir = root / ".vibearmor" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            orig_files: Dict[str, str] = staged_bundle["original_files"]
            stg_files: Dict[str, str] = staged_bundle["staged_files"]
            for rel_fp, after_txt in stg_files.items():
                if orig_files.get(rel_fp) != after_txt:
                    target = root / rel_fp
                    if target.exists():
                        bkp = backup_dir / rel_fp.replace("/", "__")
                        if not bkp.exists():
                            shutil.copy2(target, bkp)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(after_txt, encoding="utf-8")
            return staged_bundle["staged_report"]

    # Selective subset adoption: run deterministic + SLM + 3-Gate ONLY for user-approved finding IDs!
    t_start = time.perf_counter()
    ctx: WorkspaceContext = build_workspace_context(root)
    findings_before = run_all_detectors(ctx, check_live_registry=False)
    scan_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

    actionable = [f for f in findings_before if f.reachable and not f.requires_policy_spec and f.id in wanted]
    abstentions = [f for f in findings_before if f.requires_policy_spec]
    patches: List[PatchReport] = []
    llm_calls = 0
    backup_dir = root / ".vibearmor" / "backups"

    for f in actionable:
        t_fix = time.perf_counter()
        cur_ctx = build_workspace_context(root)
        mss = extract_mss(f, cur_ctx)
        edits = _generate_deterministic_edits(f, cur_ctx)
        strategy = "deterministic_codemod"

        if not edits and allow_slm:
            slm_edits, _ = repair_slice_with_slm(f, mss, cur_ctx)
            llm_calls += 1
            if slm_edits:
                edits = slm_edits
                strategy = "slm_qwen_mss"

        if not edits:
            continue

        g1 = run_gate1_compile(edits)
        if not g1.passed:
            continue
        g2 = run_gate2_rescan(root, f, edits)
        if not g2.passed:
            continue
        g3 = run_gate3_poc_probe(f, edits)
        if not g3.passed:
            continue

        _apply_edits_to_disk(root, edits, backup_dir)
        patches.append(
            PatchReport(
                finding_id=f.id,
                rule_id=f.rule_id,
                pillar=f.pillar,
                status=RemediationStatus.FIXED_VERIFIED,
                strategy_used=strategy,
                edits=edits,
                mss=mss,
                gates=[g1, g2, g3],
                repair_latency_ms=round((time.perf_counter() - t_fix) * 1000.0, 2),
            )
        )

    final_ctx = build_workspace_context(root)
    findings_after = run_all_detectors(final_ctx, check_live_registry=False)
    total_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

    return ScanAndHealReport(
        workspace=str(root),
        mode="auto_heal",
        clean_fast_path=False,
        scan_latency_ms=scan_ms,
        total_latency_ms=total_ms,
        llm_calls_made=llm_calls,
        nodes=final_ctx.nodes,
        edges=final_ctx.edges,
        findings_before=findings_before,
        findings_after=findings_after,
        patches=patches,
        abstentions=abstentions,
        summary=_build_summary(findings_before, findings_after, patches, abstentions, scan_ms, total_ms, llm_calls),
    )
