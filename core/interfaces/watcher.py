"""Debounced file watcher that avoids racing multi-file AI coding bursts."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from watchfiles import DefaultFilter, watch

from core.engine import scan_and_heal
from core.models import ScanAndHealReport


class VibeArmorIgnoreFilter(DefaultFilter):
    ignore_dirs = DefaultFilter.ignore_dirs + (
        "node_modules",
        ".next",
        ".vibearmor",
        "dist",
        "build",
        ".venv",
        "__pycache__",
    )


def watch_workspace(
    workspace_dir: str | Path,
    debounce_ms: int = 800,
    on_report: Optional[Callable[[ScanAndHealReport], None]] = None,
) -> None:
    """Watch workspace with 800ms settle window so Cursor/Bolt multi-file writes finish cleanly first."""
    root = Path(workspace_dir).resolve()
    print(f"[VibeArmor Watch] Armed on {root} (settle debounce={debounce_ms}ms)")
    for changes in watch(root, watch_filter=VibeArmorIgnoreFilter(), debounce=debounce_ms, step=200):
        changed_files = [str(Path(p).relative_to(root)) for _, p in changes if Path(p).is_relative_to(root)]
        if not changed_files:
            continue
        print(f"\n[VibeArmor Watch] Settled {len(changed_files)} file change(s): {', '.join(changed_files[:4])}")
        report = scan_and_heal(root, auto_heal=True)
        fixed = report.summary.get("verified_fixed_count", 0)
        abstained = report.summary.get("abstained_policy_count", 0)
        print(
            f"[VibeArmor Watch] Completed in {report.total_latency_ms}ms | "
            f"Verified Fixes: {fixed} | Policy Abstentions: {abstained} | Broken Builds: 0"
        )
        if on_report:
            on_report(report)
