"""Pillar 4 Remediator: Blocks Hallucinated / Slopsquatted Packages & Bumps Reachable CVEs."""

from __future__ import annotations

import difflib
import json
import re
from typing import List

from core.graph.cross_layer_graph import WorkspaceContext
from core.models import FileEdit, Finding


def _make_diff(path: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            n=2,
        )
    )


def patch_dependency(finding: Finding, ctx: WorkspaceContext) -> List[FileEdit]:
    if not finding.reachable:
        return []

    rel = finding.file_path
    before = ctx.file_contents.get(rel, "")
    if not before:
        return []

    eco = finding.metadata.get("ecosystem", "npm")
    pkg = finding.metadata.get("package", "")
    issue_kind = finding.metadata.get("issue_kind", "")
    safe_ver = finding.metadata.get("safe_version", "")
    safe_replacement = finding.metadata.get("safe_replacement_pkg")

    after = before

    if eco == "npm" and rel.endswith("package.json"):
        try:
            data = json.loads(before)
            deps = data.get("dependencies") or {}
            if pkg in deps:
                if issue_kind == "cve_outdated" and safe_ver:
                    deps[pkg] = f"^{safe_ver}"
                elif safe_replacement:
                    old_ver = deps.pop(pkg)
                    if safe_replacement not in deps:
                        deps[safe_replacement] = "latest" if "0." in str(old_ver) else old_ver
                else:
                    # Quarantine hallucinated/slopsquatted package completely!
                    deps.pop(pkg, None)
                data["dependencies"] = deps
                after = json.dumps(data, indent=2) + "\n"
        except Exception:
            pass

    elif eco == "pypi" and rel.endswith("requirements.txt"):
        lines = before.splitlines()
        new_lines = []
        for ln in lines:
            stripped = ln.strip()
            if re.match(rf"^{re.escape(pkg)}\b", stripped, re.IGNORECASE):
                if issue_kind == "cve_outdated" and safe_ver:
                    new_lines.append(f"{pkg}=={safe_ver}  # VibeArmor CVE fix")
                elif safe_replacement:
                    new_lines.append(f"{safe_replacement}  # VibeArmor replaced {pkg}")
                else:
                    new_lines.append(f"# QUARANTINED_BY_VIBEARMOR (slopsquat/hallucination): {ln}")
            else:
                new_lines.append(ln)
        after = "\n".join(new_lines) + ("\n" if before.endswith("\n") else "")

    if after != before:
        return [
            FileEdit(
                file_path=rel,
                before_content=before,
                after_content=after,
                unified_diff=_make_diff(rel, before, after),
            )
        ]
    return []
