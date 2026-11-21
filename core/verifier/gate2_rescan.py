"""Gate 2: Staged Cross-Layer Graph Re-Scan Verification."""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from typing import List

from core.detectors import run_all_detectors
from core.graph.cross_layer_graph import build_workspace_context
from core.models import FileEdit, Finding, GateCheck, Severity


def run_gate2_rescan(workspace_root: Path, target_finding: Finding, edits: List[FileEdit]) -> GateCheck:
    t0 = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="vibearmor_stage_") as tmp:
        stage_dir = Path(tmp) / "repo"
        shutil.copytree(
            workspace_root,
            stage_dir,
            ignore=shutil.ignore_patterns("node_modules", ".git", ".next", "dist", "build", "__pycache__", ".venv", ".vibearmor"),
        )
        for ed in edits:
            dest = stage_dir / ed.file_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(ed.after_content, encoding="utf-8")

        staged_ctx = build_workspace_context(stage_dir)
        after_findings = run_all_detectors(staged_ctx, check_live_registry=False)

    # Check if the SPECIFIC target finding still persists (even when multiple findings share a file!)
    still_present = False
    identity_keys = ("table", "package", "rpc_name", "policy_name", "env_key", "var_name", "func_name", "route_path")
    target_ident = {k: target_finding.metadata.get(k) for k in identity_keys if target_finding.metadata.get(k)}

    for f in after_findings:
        if not f.reachable or f.requires_policy_spec:
            continue
        if f.pillar == target_finding.pillar and f.file_path == target_finding.file_path and f.rule_id == target_finding.rule_id:
            if target_ident:
                if all(f.metadata.get(k) == v for k, v in target_ident.items()):
                    still_present = True
                    break
            else:
                if f.title == target_finding.title or abs(f.line_start - target_finding.line_start) <= 2:
                    still_present = True
                    break

    # Ensure zero new secrets or critical regressions were introduced in newly created files (e.g. Auto-BFF route)
    created_paths = {ed.file_path for ed in edits if ed.created_new}
    new_regressions = [
        f"{f.rule_id} in {f.file_path}: {f.title}"
        for f in after_findings
        if f.file_path in created_paths and f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    ms = round((time.perf_counter() - t0) * 1000.0, 2)
    passed = (not still_present) and (len(new_regressions) == 0)
    details = []
    if still_present:
        details.append(f"Target vulnerability {target_finding.rule_id} still detected in {target_finding.file_path}")
    details.extend(new_regressions)
    if passed:
        details.append(f"Target {target_finding.rule_id} eliminated; 0 new leaks across {len(edits)} staged file(s)")

    return GateCheck(
        gate_name="Gate 2 · Cross-Layer Graph Re-Scan",
        passed=passed,
        latency_ms=ms,
        summary="0 target flaws remaining & 0 new regressions introduced" if passed else "; ".join(details),
        details=details,
    )
