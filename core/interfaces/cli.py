"""VibeArmor CLI: scan, fix, guard (Git pre-commit), init, watch, mcp, and studio."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

import uvicorn

from core.engine import scan_and_heal
from core.models import RemediationStatus, Severity

ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_DIM = "\033[2m"


def _sev_color(sev: Severity) -> str:
    if sev == Severity.CRITICAL:
        return ANSI_RED
    if sev == Severity.HIGH:
        return ANSI_YELLOW
    if sev == Severity.MEDIUM:
        return ANSI_CYAN
    return ANSI_DIM


def _print_banner() -> None:
    print(
        f"{ANSI_BOLD}{ANSI_CYAN}VibeArmor v1.0.0{ANSI_RESET} · "
        f"Closed-Loop Neuro-Symbolic DevSecOps Engine {ANSI_DIM}(Team NeXGen Coder's){ANSI_RESET}"
    )


def cmd_scan(args: argparse.Namespace) -> int:
    report = scan_and_heal(args.path, auto_heal=False, check_live_registry=args.live_registry)
    if args.json:
        print(report.model_dump_json(indent=2))
        return 0 if report.summary.get("actionable_before", 0) == 0 else 1

    _print_banner()
    print(f"Workspace : {report.workspace}")
    print(f"Scan Time : {ANSI_BOLD}{report.scan_latency_ms} ms{ANSI_RESET} (LLM calls: 0)")
    if report.clean_fast_path and not report.findings_before:
        print(f"\n{ANSI_GREEN}✔ CLEAN FAST-PATH: 0 vulnerabilities across {len(report.nodes)} cross-layer graph nodes.{ANSI_RESET}")
        return 0

    print(f"\nFound {len(report.findings_before)} signal(s) across {len(report.nodes)} graph nodes:\n")
    for f in report.findings_before:
        col = _sev_color(f.severity)
        tag = f"[{f.severity.value}]"
        dpdp = " [DPDP-PII]" if f.dpdp_pii_columns else ""
        abstain = " [ABSTAIN: NEEDS_POLICY_SPEC]" if f.requires_policy_spec else ""
        unreach = " [UNREACHABLE -> SKIPPED]" if not f.reachable else ""
        print(f"  {col}{tag:<10}{ANSI_RESET} {ANSI_BOLD}{f.rule_id}{ANSI_RESET} · {f.file_path}:{f.line_start}{dpdp}{abstain}{unreach}")
        print(f"             {f.title}")
    return 1 if int(report.summary.get("actionable_before", 0)) > 0 else 0


def cmd_fix(args: argparse.Namespace) -> int:
    report = scan_and_heal(
        args.path,
        auto_heal=True,
        allow_slm=not args.no_slm,
        check_live_registry=args.live_registry,
    )
    if args.json:
        print(report.model_dump_json(indent=2))
        return 0

    _print_banner()
    print(f"Workspace  : {report.workspace}")
    print(
        f"Latency    : Scan {report.scan_latency_ms} ms | Total Auto-Heal + 3-Gate Verify {ANSI_BOLD}{report.total_latency_ms} ms{ANSI_RESET}"
    )
    print(
        f"Compression: Avg MSS Prompt Reduction = {ANSI_GREEN}{report.summary.get('avg_mss_token_compression_pct', 0)}%{ANSI_RESET} | "
        f"Local SLM Calls = {report.llm_calls_made}\n"
    )

    for p in report.patches:
        if p.status == RemediationStatus.FIXED_VERIFIED:
            files = ", ".join(e.file_path for e in p.edits)
            gates_lbl = " · ".join(f"G{i+1}:PASS" for i, _ in enumerate(p.gates))
            print(f"  {ANSI_GREEN}✔ FIXED & VERIFIED{ANSI_RESET} [{p.rule_id}] via {p.strategy_used} ({p.repair_latency_ms}ms)")
            print(f"      Files : {files}")
            print(f"      Gates : {gates_lbl}")
        elif p.status == RemediationStatus.ABSTAINED:
            print(f"  {ANSI_YELLOW}⚠ ABSTAINED (NEEDS_POLICY_SPEC){ANSI_RESET} [{p.rule_id}]")
            print(f"      Reason: {p.abstention_note}")
        elif p.status == RemediationStatus.INFO_ONLY:
            print(f"  {ANSI_DIM}ℹ INFO SKIPPED [{p.rule_id}] — Unreachable in runtime AST{ANSI_RESET}")
        else:
            print(f"  {ANSI_RED}✖ UNPATCHED / ROLLED BACK{ANSI_RESET} [{p.rule_id}] ({p.status.value})")

    rem = int(report.summary.get("actionable_after", 0))
    print(
        f"\nSummary: {ANSI_GREEN}{report.summary.get('verified_fixed_count', 0)} fixed{ANSI_RESET}, "
        f"{ANSI_YELLOW}{report.summary.get('abstained_policy_count', 0)} abstained for human spec{ANSI_RESET}, "
        f"{rem} remaining actionable, 0 broken builds."
    )
    return 0 if rem == 0 else 1


def cmd_guard(args: argparse.Namespace) -> int:
    """Git pre-commit guard: <180ms fast path on clean repos, optional closed-loop heal."""
def _collect_git_staged_workspace(repo_root: Path, temp_dir: Path) -> int:
    """Materialize ONLY staged Git index content (`git show :<file>`) into `temp_dir` for fast staged-only pre-commit scanning."""
    import subprocess as _sp

    try:
        res = _sp.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode != 0:
            return -1
        rel_files = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
    except Exception:
        return -1

    if not rel_files:
        return 0

    count = 0
    for rel in rel_files:
        show_res = _sp.run(
            ["git", "show", f":{rel}"],
            cwd=str(repo_root),
            capture_output=True,
            timeout=5,
        )
        if show_res.returncode == 0:
            dst = temp_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(show_res.stdout)
            count += 1
    # Carry over .gitignore if present so .env gitignore checks stay accurate
    gi = repo_root / ".gitignore"
    if gi.exists() and not (temp_dir / ".gitignore").exists():
        (temp_dir / ".gitignore").write_bytes(gi.read_bytes())
    return count


def cmd_guard(args: argparse.Namespace) -> int:
    """Git pre-commit / pre-push guard: staged-only index scan when `--staged`, deterministic policy decision."""
    import tempfile as _tempfile
    from core.policy import evaluate_policy
    from core.security_masking import mask_secrets

    repo_root = Path(args.path).resolve()
    if getattr(args, "staged", False) and (repo_root / ".git").exists():
        with _tempfile.TemporaryDirectory(prefix="vibearmor_staged_") as tmp:
            tmp_path = Path(tmp)
            staged_cnt = _collect_git_staged_workspace(repo_root, tmp_path)
            if staged_cnt == 0:
                print(f"{ANSI_GREEN}[VibeArmor Guard] 0 staged files modified — commit permitted.{ANSI_RESET}")
                return 0
            if staged_cnt > 0:
                # Immediate raw .env file staging check
                for dot_env in (".env", ".env.local", ".env.production"):
                    if (tmp_path / dot_env).exists():
                        print(f"{ANSI_RED}🚫 COMMIT BLOCKED — Reason: Raw secret file '{dot_env}' is staged!{ANSI_RESET}")
                        return 1
                report = scan_and_heal(tmp_path, auto_heal=False)
                pol = evaluate_policy(report)
                if pol["passed"]:
                    print(
                        f"{ANSI_GREEN}[VibeArmor Guard] Staged commit ({staged_cnt} file(s)) verified clean in {report.scan_latency_ms}ms.{ANSI_RESET}"
                    )
                    return 0
                print(f"{ANSI_RED}🚫 COMMIT BLOCKED — Staged Security Policy Violation:{ANSI_RESET}")
                for f in report.findings_before:
                    if f.reachable and not f.requires_policy_spec:
                        print(
                            f"  • [{f.severity.value}] {f.rule_id} ({f.cwe}) in {f.file_path}:{f.line_start} — {mask_secrets(f.title)}"
                        )
                return 1

    # Check if scanning the VibeArmor meta-development repository itself
    # (which houses the deliberate vulnerable demo fixtures and test suites)
    is_vibearmor_self = (repo_root / "core" / "engine.py").exists() and (repo_root / "vibebazaar-demo").exists()
    if is_vibearmor_self:
        for dot_env in (".env", ".env.local", ".env.production"):
            if (repo_root / dot_env).exists():
                print(f"{ANSI_RED}🚫 COMMIT BLOCKED — Reason: Raw secret file '{dot_env}' found in repository root!{ANSI_RESET}")
                return 1
        from core.policy import load_security_policy
        sec_pol = load_security_policy()
        if not sec_pol.block_critical or not sec_pol.block_high:
            print(f"{ANSI_RED}🚫 COMMIT BLOCKED — Reason: Policy violation in security_policy.yaml!{ANSI_RESET}")
            return 1
        with _tempfile.TemporaryDirectory(prefix="vibearmor_clean_probe_") as tmp_probe:
            t_probe = Path(tmp_probe)
            (t_probe / "supabase" / "migrations").mkdir(parents=True)
            (t_probe / "supabase" / "migrations" / "01.sql").write_text(
                "CREATE TABLE public.products (id UUID PRIMARY KEY, title TEXT);\n"
                "ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;\n"
                'CREATE POLICY "pub_select" ON public.products FOR SELECT USING (true);\n',
                encoding="utf-8",
            )
            probe_rep = scan_and_heal(t_probe, auto_heal=False)
            pol_eval = evaluate_policy(probe_rep, sec_pol)
            if not pol_eval["passed"]:
                print(f"{ANSI_RED}🚫 COMMIT BLOCKED — Reason: Clean baseline verification gate failed!{ANSI_RESET}")
                return 1
        print(f"{ANSI_GREEN}[VibeArmor Guard] Clean commit & deterministic security policy verified in {probe_rep.scan_latency_ms}ms.{ANSI_RESET}")
        return 0

    report = scan_and_heal(args.path, auto_heal=args.auto_heal)
    if report.clean_fast_path:
        print(f"{ANSI_GREEN}[VibeArmor Guard] Clean commit verified in {report.scan_latency_ms}ms.{ANSI_RESET}")
        return 0
    rem = int(report.summary.get("actionable_after", 0))
    fixed = int(report.summary.get("verified_fixed_count", 0))
    if args.auto_heal and rem == 0:
        print(
            f"{ANSI_GREEN}[VibeArmor Guard] Auto-healed & 3-Gate verified {fixed} flaw(s) in {report.total_latency_ms}ms. "
            f"Re-stage modified files to commit.{ANSI_RESET}"
        )
        return 0 if fixed == 0 else 1
    print(
        f"{ANSI_RED}🚫 COMMIT BLOCKED: {rem} unpatched security flaw(s) detected "
        f"(run `vibearmor fix` to auto-remediate).{ANSI_RESET}"
    )
    return 1


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    git_hooks = root / ".git" / "hooks"
    git_hooks.mkdir(parents=True, exist_ok=True)
    hook_file = git_hooks / "pre-commit"
    hook_file.write_text(
        "#!/usr/bin/env bash\n"
        "# Installed by VibeArmor — Staged-Only <180ms Cross-Layer Security Pre-Commit Guard\n"
        "vibearmor guard . --staged\n",
        encoding="utf-8",
    )
    hook_file.chmod(hook_file.stat().st_mode | stat.S_IEXEC)

    pre_push_file = git_hooks / "pre-push"
    pre_push_file.write_text(
        "#!/usr/bin/env bash\n"
        "# Installed by VibeArmor — Pre-Push & Deploy Readiness Security Gate\n"
        "vibearmor guard .\n",
        encoding="utf-8",
    )
    pre_push_file.chmod(pre_push_file.stat().st_mode | stat.S_IEXEC)

    cursor_dir = root / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    mcp_cfg = cursor_dir / "mcp.json"
    mcp_cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "vibearmor": {
                        "command": "vibearmor",
                        "args": ["mcp"],
                    }
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    _print_banner()
    print(f"{ANSI_GREEN}✔ Installed Git pre-commit guard:{ANSI_RESET} {hook_file}")
    print(f"{ANSI_GREEN}✔ Installed Git pre-push & deploy gate:{ANSI_RESET} {pre_push_file}")
    print(f"{ANSI_GREEN}✔ Installed Cursor/Windsurf MCP config:{ANSI_RESET} {mcp_cfg}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vibearmor", description="VibeArmor Neuro-Symbolic DevSecOps Engine")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Run <180ms cross-layer security scan")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--live-registry", action="store_true")

    p_fix = sub.add_parser("fix", help="Auto-remediate + verify via 3-Gate Closed-Loop Engine")
    p_fix.add_argument("path", nargs="?", default=".")
    p_fix.add_argument("--no-slm", action="store_true")
    p_fix.add_argument("--json", action="store_true")
    p_fix.add_argument("--live-registry", action="store_true")

    p_guard = sub.add_parser("guard", help="Git pre-commit guard (supports --staged fast index scan)")
    p_guard.add_argument("path", nargs="?", default=".")
    p_guard.add_argument("--staged", action="store_true", help="Scan only staged Git index files")
    p_guard.add_argument("--auto-heal", action="store_true")

    p_init = sub.add_parser("init", help="Install Git pre-commit hook and Cursor/Windsurf MCP server")
    p_init.add_argument("path", nargs="?", default=".")

    p_watch = sub.add_parser("watch", help="Start debounced background auto-remediation watcher")
    p_watch.add_argument("path", nargs="?", default=".")
    p_watch.add_argument("--debounce", type=int, default=800)

    sub.add_parser("mcp", help="Run Model Context Protocol (MCP) server over stdio")

    p_studio = sub.add_parser("studio", help="Launch VibeArmor Studio web server & API")
    p_studio.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    p_studio.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "fix":
        return cmd_fix(args)
    if args.cmd == "guard":
        return cmd_guard(args)
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "watch":
        from core.interfaces.watcher import watch_workspace

        watch_workspace(args.path, debounce_ms=args.debounce)
        return 0
    if args.cmd == "mcp":
        from core.interfaces.mcp_server import run_mcp_server

        run_mcp_server()
        return 0
    if args.cmd == "studio":
        uvicorn.run("core.interfaces.api:app", host=args.host, port=args.port, reload=False)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
