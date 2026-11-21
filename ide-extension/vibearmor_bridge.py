#!/usr/bin/env python3
"""VibeArmor Live Two-Way Editor Bridge & Hard Git Pre-Push Gate (Zero External Dependencies).

Works with ANY local code editor (VS Code, Cursor, Windsurf, Zed, Neovim, JetBrains, Trae):
  1. Pairs a local project directory with the VibeArmor Web Application via `va_pair_...` token.
  2. Installs `.git/hooks/pre-push` & `.git/hooks/pre-commit` to HARD-BLOCK unsafe Git pushes.
  3. Syncs local source files UP to VibeArmor (`POST /api/extension/pair/sync-up`) so you can inspect
     the interactive Code Structure Graph and Vulnerable-vs-Correct Diff in the browser or editor.
  4. Syncs user-approved surgical fixes DOWN (`GET /api/extension/pair/{token}/pending-fixes`),
     modifying ONLY the approved vulnerable lines while leaving clean files 100% untouched (0 bytes altered).

Usage:
  python3 vibearmor_bridge.py --server http://127.0.0.1:8000 --token va_pair_xxxx --dir . --watch
  python3 vibearmor_bridge.py --server http://127.0.0.1:8000 --dir . --pre-push-gate
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SKIP_DIRS = {".git", "node_modules", ".vibearmor", "__pycache__", ".next", "dist", "build", ".venv", "venv"}
SCANNABLE_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".sql", ".json", ".yaml", ".yml",
    ".toml", ".md", ".env", ".local", ".example", ".txt", ".html", ".css", ".sh",
}


def _http_json(method: str, url: str, payload: Optional[ dict ] = None, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _detect_git_branch(root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(root),
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return out or "main"
    except Exception:
        return "main"


def collect_project_files(root: Path, max_files: int = 250) -> List[Dict[str, str]]:
    collected: List[Dict[str, str]] = []
    for p in sorted(root.rglob("*")):
        if len(collected) >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if (
            p.suffix.lower() in SCANNABLE_EXTS
            or p.name.startswith(".env")
            or p.name in ("Dockerfile", "Makefile", ".gitignore")
        ):
            try:
                if p.stat().st_size <= 300_000:
                    rel = str(p.relative_to(root)).replace("\\", "/")
                    collected.append({"path": rel, "content": p.read_text(encoding="utf-8", errors="replace")})
            except Exception:
                pass
    return collected


def compute_tree_fingerprint(files: List[Dict[str, str]]) -> str:
    h = hashlib.sha256()
    for item in files:
        h.update(item["path"].encode("utf-8"))
        h.update(b"\0")
        h.update(item["content"].encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def install_hard_git_hooks(root: Path, server_url: str, token: str, editor: str) -> Optional[Path]:
    git_dir = root / ".git"
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    meta_dir = root / ".vibearmor"
    meta_dir.mkdir(parents=True, exist_ok=True)
    local_bridge = meta_dir / "vibearmor_bridge.py"
    try:
        if Path(__file__).resolve() != local_bridge.resolve():
            shutil.copy2(Path(__file__).resolve(), local_bridge)
    except Exception:
        pass

    cfg_file = meta_dir / "pairing.json"
    cfg_file.write_text(
        json.dumps({"server_url": server_url, "pair_token": token, "editor": editor}, indent=2),
        encoding="utf-8",
    )

    hook_body = f"""#!/usr/bin/env sh
# VibeArmor Hard Pre-Push & Pre-Commit Security Gate (Windows + macOS + Linux)
set -e
if command -v python >/dev/null 2>&1; then
  PY_BIN="python"
else
  PY_BIN="python3"
fi
"$PY_BIN" "{local_bridge.as_posix()}" --dir "{root.as_posix()}" --server "{server_url}" --token "{token}" --editor "{editor}" --pre-push-gate
"""
    for hook_name in ("pre-push", "pre-commit"):
        hp = hooks_dir / hook_name
        hp.write_text(hook_body, encoding="utf-8")
        hp.chmod(hp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hooks_dir / "pre-push"


def run_offline_local_scan(files: List[Dict[str, str]]) -> Tuple[bool, int, List[Dict[str, object]]]:
    """Built-in zero-dependency local security scanner when remote Studio server is unreachable (e.g. cloud preview)."""
    findings: List[Dict[str, object]] = []
    secret_re = re.compile(r"\b(?:sk_live_|sk_test_|rzp_live_|ghp_[A-Za-z0-9]{16}|github_pat_[A-Za-z0-9_]{16}|AIza[0-9A-Za-z_-]{16})")
    sql_fstr_re = re.compile(r"\.execute\s*\(\s*f[\"']\s*SELECT\b", re.IGNORECASE)
    for item in files:
        rel = item["path"]
        base = rel.split("/")[-1]
        if base in (".env", ".env.local", ".env.production") or rel.startswith(("eval/", "tests/")):
            continue
        for idx, ln in enumerate(item["content"].splitlines(), start=1):
            if secret_re.search(ln):
                findings.append({"rule_id": "VA-SEC-001", "file_path": rel, "line_start": idx, "title": "Hardcoded live API credential"})
            if rel.endswith(".py") and "# nosec" not in ln.lower():
                if sql_fstr_re.search(ln):
                    findings.append({"rule_id": "VA-TNT-001", "file_path": rel, "line_start": idx, "title": "SQL Injection via f-string execute()"})
                if re.search(r"\bshell\s*=\s*True\b", ln):
                    findings.append({"rule_id": "VA-TNT-003", "file_path": rel, "line_start": idx, "title": "Command Injection via shell=True"})
    score = max(0, 100 - len(findings) * 18)
    return (len(findings) == 0, score, findings)


def run_pre_push_gate(root: Path, server_url: str, token: str, editor: str) -> int:
    files = collect_project_files(root)
    branch = _detect_git_branch(root)
    print(f"[VibeArmor Gate] Auditing '{root.name}' ({len(files)} files on branch '{branch}')...")
    try:
        if token:
            res = _http_json(
                "POST",
                f"{server_url.rstrip('/')}/api/extension/pair/sync-up",
                {
                    "pair_token": token,
                    "editor": editor,
                    "workspace_name": root.name,
                    "local_path": str(root),
                    "branch": branch,
                    "files": files,
                },
            )
            ready = bool(res.get("ready_to_push"))
            score = res.get("security_score", 0)
            blocking = res.get("open_threats", 0)
            proj_id = res.get("project_id", "")
            findings = res.get("findings", [])
        else:
            res = _http_json(
                "POST",
                f"{server_url.rstrip('/')}/api/extension/verify-readiness",
                {
                    "editor": editor,
                    "workspace_name": root.name,
                    "branch": branch,
                    "files": files,
                    "include_proposals": False,
                },
            )
            ready = bool(res.get("ready_to_push"))
            score = res.get("security_score", 0)
            blocking = res.get("blocking_count", 0)
            proj_id = ""
            findings = res.get("findings", [])
    except Exception:
        ready, score, findings = run_offline_local_scan(files)
        blocking = len(findings)
        proj_id = ""
        print(f"[VibeArmor Gate] Running Standalone Offline Security Engine (Score: {score}/100)...")

    if ready:
        print(f"[VibeArmor Gate] PASS ({score}/100) — 0 open threats. Safe to push to GitHub & deploy!")
        return 0

    print("\n======================================================================")
    print(f"  STOP: GIT PUSH & DEPLOY BLOCKED BY VIBEARMOR ({blocking} Open Threats · Score {score}/100)")
    print("======================================================================")
    for f in findings[:10]:
        print(f"  ✖ [{f.get('rule_id')}] {f.get('file_path')}:{f.get('line_start')} — {f.get('title')}")
    if proj_id:
        print(f"\n  Review Vulnerable vs. Correct Diff & Approve Fixes:")
        print(f"  -> {server_url.rstrip('/')}/?project={proj_id}&step=step3_diff")
    print("======================================================================\n")
    return 1


def apply_pending_down_sync(root: Path, server_url: str, token: str) -> bool:
    res = _http_json("GET", f"{server_url.rstrip('/')}/api/extension/pair/{token}/pending-fixes")
    pending_files: Dict[str, str] = res.get("pending_files") or {}
    if not pending_files:
        return False

    backup_dir = root / ".vibearmor" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    applied_paths: List[str] = []

    for rel_fp, new_content in pending_files.items():
        clean_rel = rel_fp.lstrip("/").replace("..", "_")
        target = (root / clean_rel).resolve()
        if not str(target).startswith(str(root.resolve())):
            continue
        if target.exists():
            bkp = backup_dir / clean_rel.replace("/", "__")
            if not bkp.exists():
                shutil.copy2(target, bkp)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(new_content, encoding="utf-8")
        applied_paths.append(clean_rel)

    _http_json(
        "POST",
        f"{server_url.rstrip('/')}/api/extension/pair/{token}/ack-fixes",
        {"applied_files": applied_paths},
    )
    print(f"[VibeArmor Sync] Adopted {len(applied_paths)} user-approved surgical file(s) from Web Studio:")
    for ap in applied_paths:
        print(f"  ✓ Patched {ap} (all non-vulnerable files left 100% untouched)")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="VibeArmor Two-Way Local Editor Bridge & Push Gate")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="VibeArmor Web App URL")
    parser.add_argument("--token", default="", help="Pairing token (va_pair_...) generated in VibeArmor Studio")
    parser.add_argument("--dir", default=".", help="Local project workspace directory")
    parser.add_argument("--editor", default="Cursor / VS Code", help="Editor label")
    parser.add_argument("--watch", action="store_true", help="Continuously two-way sync local folder <-> Web App")
    parser.add_argument("--once", action="store_true", help="Run a single two-way sync pass and exit")
    parser.add_argument("--pre-push-gate", action="store_true", help="Run hard git pre-push verification gate")
    args = parser.parse_args()

    root = Path(args.dir).resolve()
    if not root.is_dir():
        print(f"Directory not found: {root}", file=sys.stderr)
        return 1

    if args.pre_push_gate:
        return run_pre_push_gate(root, args.server, args.token, args.editor)

    if not args.token:
        print("Provide --token va_pair_... from VibeArmor Web Studio (Code Editor Extension -> Pair Workspace).", file=sys.stderr)
        return 1

    hook_path = install_hard_git_hooks(root, args.server, args.token, args.editor)
    print(f"[VibeArmor] Hard git pre-push & pre-commit gate active at: {hook_path}")

    last_fp = ""
    warned_offline = False
    while True:
        files = collect_project_files(root)
        fp = compute_tree_fingerprint(files)
        try:
            # 1. Pull any user-approved surgical fixes from Web Studio first
            pulled = apply_pending_down_sync(root, args.server, args.token)
            if pulled:
                last_fp = ""
                files = collect_project_files(root)
                fp = compute_tree_fingerprint(files)

            # 2. Push local workspace changes up to VibeArmor if changed
            if fp != last_fp:
                branch = _detect_git_branch(root)
                sync_res = _http_json(
                    "POST",
                    f"{args.server.rstrip('/')}/api/extension/pair/sync-up",
                    {
                        "pair_token": args.token,
                        "editor": args.editor,
                        "workspace_name": root.name,
                        "local_path": str(root),
                        "branch": branch,
                        "files": files,
                    },
                )
                last_fp = fp
                warned_offline = False
                verdict = "READY TO PUSH" if sync_res.get("ready_to_push") else f"BLOCKED ({sync_res.get('open_threats')} threats)"
                print(
                    f"[VibeArmor Sync] Paired Workspace '{root.name}' synced -> {verdict} "
                    f"(Score {sync_res.get('security_score')}/100) | Studio: {args.server.rstrip('/')}/?project={sync_res.get('project_id')}&step=step1_graph"
                )
        except Exception as exc:
            if not warned_offline:
                warned_offline = True
                if ".arena.site" in args.server or ".e2b.app" in args.server:
                    print(
                        f"[VibeArmor] Note: Cloud preview URL ({args.server}) requires browser cookies — "
                        "switched automatically to Standalone Local Security Watch Mode! "
                        "(Run local Studio on http://127.0.0.1:8000 for live 2-way browser sync.)"
                    )
                else:
                    print(f"[VibeArmor] Server {args.server} unreachable ({exc}) — running Standalone Local Watch Mode.")
            if fp != last_fp:
                last_fp = fp
                ready, score, findings = run_offline_local_scan(files)
                verdict = "READY TO PUSH" if ready else f"BLOCKED ({len(findings)} threats)"
                print(f"[VibeArmor Local Watch] '{root.name}' ({len(files)} files) -> {verdict} (Score {score}/100)")
                for f in findings[:6]:
                    print(f"  ✖ [{f['rule_id']}] {f['file_path']}:{f['line_start']} — {f['title']}")

        if args.once or not args.watch:
            break
        time.sleep(2.5)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
