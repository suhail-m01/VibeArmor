"""VibeArmor v2.0 Production FastAPI Server:
  - Multi-Workspace Project Registry (Live GitHub Repo Clone, .zip Archive Upload, Reference Apps)
  - Real-time NDJSON Streaming Neuro-Symbolic Scan & Auto-Heal Telemetry
  - Git `.patch`, Healed `.zip`, and Printable DPDP/OWASP Verification Certificate Exports
  - Genuinely Executable Live SQLite + Dynamic Python Exploit Runner
  - Live Read-Only Supabase PostgREST Exposure Auditor
"""

from __future__ import annotations

import io
import json
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.graph.sql_rls_parser import DPDP_PII_PATTERNS
from core.engine import scan_and_heal
from core.exporter import (
    build_audit_certificate_html,
    build_git_patch,
    build_workspace_zip,
    compute_security_score,
    compute_workspace_digest,
)
from core.github_sync import (
    build_local_git_push_script,
    build_offline_git_push_commands,
    clear_github_config,
    discover_local_system_github_token,
    load_saved_github_config,
    push_surgical_fixes_to_github,
    save_github_config,
    verify_github_token_access,
)
from core.agents.langgraph_workflow import (
    build_workspace_evidence_bundle,
    run_agentic_security_workflow_on_workspace,
)
from core.policy import SecurityPolicyConfig, load_security_policy, save_security_policy
from core.rag.security_rag import search_security_knowledge_base
from core.interfaces.live_target import execute_live_exploit_suite, execute_workspace_exploit_suite
from core.models import Pillar, ScanAndHealReport
from core.remediators.slm_mss import get_slm_status
from core.surgical_engine import adopt_selected_proposals, stage_surgical_proposals

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VSIX_PACKAGE_PATH = PROJECT_ROOT / "ide-extension" / "vibearmor-guard-3.6.0.vsix"
BRIDGE_SCRIPT_PATH = PROJECT_ROOT / "ide-extension" / "vibearmor_bridge.py"
BROWSER_ZIP_PATH = PROJECT_ROOT / "browser-extension" / "vibearmor-browser-guard-3.0.0.zip"
DEMO_TEMPLATE_DIR = PROJECT_ROOT / "vibebazaar-demo" / "template_vulnerable"
DEMO_WORKSPACE_DIR = PROJECT_ROOT / "vibebazaar-demo" / "workspace"
WORKSPACES_STORE = PROJECT_ROOT / "workspaces_store"
PAIRINGS_FILE = WORKSPACES_STORE / "_pairings.json"
EVAL_RESULTS_PATH = PROJECT_ROOT / "eval" / "results.json"
STATIC_UI_DIR = PROJECT_ROOT / "core" / "static_ui"

SKIP_DIRS = {".git", "node_modules", ".vibearmor", "__pycache__", ".next", "dist", "build", ".venv", "venv"}
TEXT_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".sql", ".json", ".yaml", ".yml",
    ".toml", ".md", ".env", ".local", ".example", ".txt", ".html", ".css", ".sh",
}

app = FastAPI(
    title="VibeArmor v2.0 — Neuro-Symbolic DevSecOps Platform",
    version="2.0.0",
    description="Track 03 · R1: Vibe-coded and vulnerable — Team NeXGen Coder's",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory cache of latest reports per project_id (backed on disk in WORKSPACES_STORE)
_PROJECT_META: Dict[str, Dict[str, Any]] = {}
_PROJECT_REPORTS: Dict[str, ScanAndHealReport] = {}
_STAGED_BUNDLES: Dict[str, Dict[str, Any]] = {}
_EXTENSION_EVENTS: List[Dict[str, Any]] = []
_PAIRING_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _load_pairings_from_disk() -> None:
    if PAIRINGS_FILE.exists() and not _PAIRING_SESSIONS:
        try:
            raw = json.loads(PAIRINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                _PAIRING_SESSIONS.update(raw)
        except Exception:
            pass


def _save_pairings_to_disk() -> None:
    WORKSPACES_STORE.mkdir(parents=True, exist_ok=True)
    PAIRINGS_FILE.write_text(json.dumps(_PAIRING_SESSIONS, indent=2), encoding="utf-8")


def _persist_project_meta(pid: str, meta: Dict[str, Any]) -> None:
    if pid == "vibebazaar-india":
        return
    proj_root = WORKSPACES_STORE / pid
    if proj_root.exists():
        (proj_root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


class PairCreateRequest(BaseModel):
    editor: str = "Cursor"
    workspace_name: str = "local-editor-workspace"
    project_id: Optional[str] = None


class PairSyncUpRequest(BaseModel):
    pair_token: str
    editor: str = "Cursor"
    workspace_name: str = "local-editor-workspace"
    local_path: str = "."
    branch: str = "main"
    files: List[Dict[str, str]] = Field(default_factory=list)


class PairAckFixesRequest(BaseModel):
    applied_files: List[str] = Field(default_factory=list)


class BrowserRepoCheckRequest(BaseModel):
    repo_url: str = ""
    page_host: str = ""
    pair_token: str = ""
    scan_if_missing: bool = False


class AdoptFixesRequest(BaseModel):
    selected_finding_ids: List[str] = Field(default_factory=list)


class GitHubPushRequest(BaseModel):
    repo_url: Optional[str] = None
    github_token: str
    mode: str = "pull_request"  # "pull_request" | "direct_commit"
    base_branch: Optional[str] = None
    commit_message: Optional[str] = None
    pr_title: Optional[str] = None


class ExtensionVerifyRequest(BaseModel):
    editor: str = "Cursor"
    workspace_name: str = "my-vibe-app"
    branch: str = "main"
    project_id: Optional[str] = None
    files: List[Dict[str, str]] = Field(default_factory=list)
    include_proposals: bool = True


class SandboxFile(BaseModel):
    path: str
    content: str


class SandboxRequest(BaseModel):
    files: List[SandboxFile] = Field(default_factory=list)
    auto_heal: bool = True
    allow_slm: bool = True


class GitHubImportRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = None
    subpath: Optional[str] = None


class ExploitProbeRequest(BaseModel):
    sqli_payload: str = "' OR '1'='1"
    caller_role: str = "anon"
    caller_uid: str = ""
    razorpay_order_id: str = "VB-MYS-9083"
    razorpay_payment_id: str = "pay_forged_zero_rupee_00"
    razorpay_signature: str = ""


class SupabaseLiveAuditRequest(BaseModel):
    supabase_url: str
    anon_key: str


def _read_workspace_files(ws: Path, max_files: int = 300) -> Dict[str, str]:
    files: Dict[str, str] = {}
    count = 0
    for p in sorted(ws.rglob("*")):
        if count >= max_files:
            break
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in TEXT_EXTS or p.name.startswith(".env") or p.name in ("Dockerfile", "Makefile", ".gitignore"):
            if p.stat().st_size <= 250_000:
                rel = str(p.relative_to(ws)).replace("\\", "/")
                files[rel] = p.read_text(encoding="utf-8", errors="replace")
                count += 1
    return files


def _ensure_default_projects() -> None:
    WORKSPACES_STORE.mkdir(parents=True, exist_ok=True)
    _load_pairings_from_disk()
    if not DEMO_WORKSPACE_DIR.exists() and DEMO_TEMPLATE_DIR.exists():
        shutil.copytree(DEMO_TEMPLATE_DIR, DEMO_WORKSPACE_DIR)

    if "vibebazaar-india" not in _PROJECT_META and DEMO_WORKSPACE_DIR.exists():
        _PROJECT_META["vibebazaar-india"] = {
            "id": "vibebazaar-india",
            "name": "VibeBazaar India (D2C + B2B Marketplace)",
            "source_type": "reference",
            "source_label": "vibebazaar-india · Next.js + FastAPI + Supabase + Razorpay",
            "workspace_path": str(DEMO_WORKSPACE_DIR),
            "template_path": str(DEMO_TEMPLATE_DIR),
            "created_at": time.time(),
        }
    # Always discover any persisted workspaces on disk
    for sub in sorted(WORKSPACES_STORE.iterdir()):
        meta_f = sub / "meta.json"
        if sub.is_dir() and meta_f.exists():
            try:
                m = json.loads(meta_f.read_text(encoding="utf-8"))
                pid = m["id"]
                if pid not in _PROJECT_META and Path(m["workspace_path"]).exists():
                    _PROJECT_META[pid] = m
            except Exception:
                pass


def _get_or_scan_project(project_id: str) -> tuple[Dict[str, Any], ScanAndHealReport]:
    _ensure_default_projects()
    meta = _PROJECT_META.get(project_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    ws = Path(meta["workspace_path"])
    if not ws.exists():
        raise HTTPException(status_code=404, detail="Workspace directory missing on disk.")
    if project_id not in _PROJECT_REPORTS:
        _PROJECT_REPORTS[project_id] = scan_and_heal(ws, auto_heal=False)
    return meta, _PROJECT_REPORTS[project_id]


def _normalize_github_url(raw: str) -> tuple[str, str]:
    s = raw.strip()
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", s):
        s = f"https://github.com/{s}"
    parsed = urlparse(s)
    if parsed.scheme not in ("http", "https") or parsed.netloc.lower() not in ("github.com", "www.github.com"):
        raise HTTPException(status_code=400, detail="Please enter a valid public GitHub URL (https://github.com/owner/repo).")
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="GitHub URL must include owner and repository name.")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    if not re.match(r"^[A-Za-z0-9_.-]+$", owner) or not re.match(r"^[A-Za-z0-9_.-]+$", repo):
        raise HTTPException(status_code=400, detail="Invalid characters in GitHub owner/repository.")
    return f"https://github.com/{owner}/{repo}.git", f"{owner}/{repo}"


# ==================== MULTI-WORKSPACE PROJECT ENDPOINTS ====================


@app.get("/api/projects")
def api_list_projects() -> Dict[str, Any]:
    _ensure_default_projects()
    items: List[Dict[str, Any]] = []
    for pid, meta in _PROJECT_META.items():
        ws = Path(meta["workspace_path"])
        if not ws.exists():
            continue
        rep = _PROJECT_REPORTS.get(pid) or scan_and_heal(ws, auto_heal=False)
        _PROJECT_REPORTS[pid] = rep
        score = compute_security_score(rep)
        active_cnt = (
            rep.summary.get("actionable_after", 0)
            if rep.mode == "auto_heal"
            else rep.summary.get("actionable_before", 0)
        )
        items.append(
            {
                "id": pid,
                "name": meta["name"],
                "source_type": meta["source_type"],
                "source_label": meta["source_label"],
                "security_score": score,
                "mode": rep.mode,
                "actionable_open": active_cnt,
                "verified_fixed": rep.summary.get("verified_fixed_count", 0),
                "abstained": rep.summary.get("abstained_policy_count", 0),
                "scan_latency_ms": rep.scan_latency_ms,
                "node_count": len(rep.nodes),
            }
        )
    return {"projects": items}


@app.post("/api/projects/github")
def api_import_github_repo(req: GitHubImportRequest) -> Dict[str, Any]:
    _ensure_default_projects()
    clone_url, slug = _normalize_github_url(req.repo_url)
    branch_clean = req.branch.strip() if req.branch and req.branch.strip() else None
    subpath_clean = req.subpath.strip("/") if req.subpath and req.subpath.strip("/") else None

    # Deduplicate: reuse existing workspace ID when importing the same GitHub slug + branch + subpath!
    existing_pid: Optional[str] = None
    for cand_pid, cand_meta in list(_PROJECT_META.items()):
        if (
            cand_meta.get("source_type") == "github"
            and cand_meta.get("github_repo_url", "").lower() == f"https://github.com/{slug}".lower()
            and (cand_meta.get("github_branch") or None) == branch_clean
            and (cand_meta.get("github_subpath") or None) == subpath_clean
        ):
            existing_pid = cand_pid
            break

    pid = existing_pid or f"gh-{re.sub(r'[^a-z0-9-]+', '-', slug.lower()).strip('-')}"
    if not existing_pid and pid in _PROJECT_META:
        pid = f"{pid}-{uuid.uuid4().hex[:5]}"

    proj_root = WORKSPACES_STORE / pid
    clone_dest = proj_root / "raw_clone_tmp"
    ws_dest = proj_root / "workspace"
    snap_dest = proj_root / "initial_snapshot"
    shutil.rmtree(clone_dest, ignore_errors=True)
    proj_root.mkdir(parents=True, exist_ok=True)

    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch_clean and re.match(r"^[A-Za-z0-9_./-]+$", branch_clean):
        cmd.extend(["--branch", branch_clean])
    cmd.extend([clone_url, str(clone_dest)])

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=35, env=env, check=False)
    except subprocess.TimeoutExpired:
        shutil.rmtree(clone_dest, ignore_errors=True)
        if not existing_pid:
            shutil.rmtree(proj_root, ignore_errors=True)
        raise HTTPException(status_code=408, detail="Git clone timed out after 35s. Try a smaller repo or subpath.")

    if proc.returncode != 0 or not clone_dest.exists():
        err_msg = (proc.stderr or proc.stdout or "Repository not found or private.").strip().splitlines()[-1]
        shutil.rmtree(clone_dest, ignore_errors=True)
        if not existing_pid:
            shutil.rmtree(proj_root, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Git clone failed: {err_msg}")

    # Remove .git metadata & optionally narrow to subpath
    shutil.rmtree(clone_dest / ".git", ignore_errors=True)
    src_dir = clone_dest
    if subpath_clean:
        cand = (clone_dest / subpath_clean).resolve()
        if not str(cand).startswith(str(clone_dest.resolve())) or not cand.is_dir():
            shutil.rmtree(clone_dest, ignore_errors=True)
            if not existing_pid:
                shutil.rmtree(proj_root, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Subpath '{req.subpath}' not found inside repository.")
        src_dir = cand

    shutil.rmtree(ws_dest, ignore_errors=True)
    shutil.rmtree(snap_dest, ignore_errors=True)
    shutil.copytree(src_dir, ws_dest, ignore=shutil.ignore_patterns("node_modules", ".git", ".next", "dist", "build"))
    shutil.copytree(ws_dest, snap_dest)
    shutil.rmtree(clone_dest, ignore_errors=True)
    _STAGED_BUNDLES.pop(pid, None)

    meta = {
        "id": pid,
        "name": slug + (f" ({subpath_clean})" if subpath_clean else ""),
        "source_type": "github",
        "source_label": f"github.com/{slug}",
        "github_repo_url": f"https://github.com/{slug}",
        "github_branch": branch_clean,
        "github_subpath": subpath_clean,
        "adopted": False,
        "workspace_path": str(ws_dest),
        "template_path": str(snap_dest),
        "created_at": time.time(),
    }
    (proj_root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    _PROJECT_META[pid] = meta

    report = scan_and_heal(ws_dest, auto_heal=False)
    _PROJECT_REPORTS[pid] = report
    return _serialize_project_detail(pid, meta, report)


@app.delete("/api/projects/{project_id}")
def api_delete_project(project_id: str) -> Dict[str, Any]:
    _ensure_default_projects()
    if project_id == "vibebazaar-india":
        raise HTTPException(status_code=400, detail="Built-in reference workspace cannot be deleted; use Reset instead.")
    meta = _PROJECT_META.pop(project_id, None)
    _PROJECT_REPORTS.pop(project_id, None)
    _STAGED_BUNDLES.pop(project_id, None)
    proj_root = WORKSPACES_STORE / project_id
    if proj_root.exists():
        shutil.rmtree(proj_root, ignore_errors=True)
    if not meta and not proj_root.exists():
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    return {"deleted": True, "project_id": project_id}


@app.post("/api/projects/upload-zip")
async def api_upload_zip(
    file: UploadFile = File(...),
    project_name: Optional[str] = Form(default=None),
) -> Dict[str, Any]:
    _ensure_default_projects()
    raw_bytes = await file.read()
    if len(raw_bytes) > 35 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="ZIP archive exceeds 35 MB limit.")

    base_label = (project_name or (file.filename or "uploaded-project").removesuffix(".zip")).strip() or "uploaded-repo"
    safe_slug = re.sub(r"[^a-z0-9-]+", "-", base_label.lower()).strip("-")[:28] or "zip"
    pid = f"zip-{safe_slug}-{uuid.uuid4().hex[:6]}"
    proj_root = WORKSPACES_STORE / pid
    extract_raw = proj_root / "raw_zip"
    ws_dest = proj_root / "workspace"
    snap_dest = proj_root / "initial_snapshot"
    extract_raw.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            for member in zf.infolist():
                if member.is_dir():
                    continue
                if any(part in SKIP_DIRS for part in Path(member.filename).parts):
                    continue
                target_path = (extract_raw / member.filename).resolve()
                if os.path.commonpath([str(extract_raw.resolve()), str(target_path)]) != str(extract_raw.resolve()):
                    raise HTTPException(status_code=400, detail="Blocked unsafe Zip-Slip path traversal entry.")
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src_f, target_path.open("wb") as dst_f:
                    shutil.copyfileobj(src_f, dst_f)
    except zipfile.BadZipFile:
        shutil.rmtree(proj_root, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid .zip archive.")

    # Unwrap single top-level wrapper directory (e.g. repo-main/) without unwrapping standard source folders (src/, supabase/, etc.)
    known_src_dirs = {
        "src", "supabase", "app", "api", "backend", "frontend", "scripts",
        "tests", "pages", "components", "lib", "public", "server", "client",
    }
    top_entries = [p for p in extract_raw.iterdir() if p.name != "__MACOSX"]
    root_src = (
        top_entries[0]
        if len(top_entries) == 1 and top_entries[0].is_dir() and top_entries[0].name.lower() not in known_src_dirs
        else extract_raw
    )
    shutil.copytree(root_src, ws_dest)
    shutil.copytree(ws_dest, snap_dest)
    shutil.rmtree(extract_raw, ignore_errors=True)

    meta = {
        "id": pid,
        "name": base_label,
        "source_type": "zip",
        "source_label": f"Uploaded Archive · {file.filename or 'project.zip'}",
        "workspace_path": str(ws_dest),
        "template_path": str(snap_dest),
        "created_at": time.time(),
    }
    (proj_root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    _PROJECT_META[pid] = meta

    report = scan_and_heal(ws_dest, auto_heal=False)
    _PROJECT_REPORTS[pid] = report
    return _serialize_project_detail(pid, meta, report)


def _serialize_project_detail(pid: str, meta: Dict[str, Any], report: ScanAndHealReport) -> Dict[str, Any]:
    ws = Path(meta["workspace_path"])
    tpl = Path(meta["template_path"])
    files = _read_workspace_files(ws)
    before_files = _read_workspace_files(tpl) if tpl.exists() else files
    digest = compute_workspace_digest(ws)
    score = compute_security_score(report)
    breach = execute_workspace_exploit_suite(pid, ws, report)
    return {
        "project": {
            "id": pid,
            "name": meta["name"],
            "source_type": meta["source_type"],
            "source_label": meta["source_label"],
            "github_repo_url": meta.get("github_repo_url"),
            "github_branch": meta.get("github_branch"),
            "adopted": bool(meta.get("adopted", False)),
            "security_score": score,
            "digest": digest,
        },
        "report": report.model_dump(),
        "files": files,
        "before_files": before_files,
        "breach": breach,
    }


@app.get("/api/projects/{project_id}")
def api_get_project(project_id: str) -> Dict[str, Any]:
    meta, report = _get_or_scan_project(project_id)
    return _serialize_project_detail(project_id, meta, report)


@app.post("/api/projects/{project_id}/heal")
def api_heal_project(project_id: str) -> Dict[str, Any]:
    meta, _ = _get_or_scan_project(project_id)
    ws = Path(meta["workspace_path"])
    report = scan_and_heal(ws, auto_heal=True, allow_slm=True)
    _PROJECT_REPORTS[project_id] = report
    return _serialize_project_detail(project_id, meta, report)


@app.post("/api/projects/{project_id}/heal-stream")
def api_heal_project_stream(project_id: str) -> StreamingResponse:
    meta, _ = _get_or_scan_project(project_id)
    ws = Path(meta["workspace_path"])
    ev_queue: queue.Queue[Optional[Dict[str, Any]]] = queue.Queue()

    def _worker() -> None:
        try:
            rep = scan_and_heal(
                ws,
                auto_heal=True,
                allow_slm=True,
                on_event=lambda ev: ev_queue.put({"type": "progress", "event": ev}),
            )
            _PROJECT_REPORTS[project_id] = rep
            full_state = _serialize_project_detail(project_id, meta, rep)
            ev_queue.put({"type": "complete", "payload": full_state})
        except Exception as exc:
            ev_queue.put({"type": "error", "message": str(exc)})
        finally:
            ev_queue.put(None)

    threading.Thread(target=_worker, daemon=True).start()

    def _gen() -> Iterator[bytes]:
        while True:
            item = ev_queue.get()
            if item is None:
                break
            yield (json.dumps(item) + "\n").encode("utf-8")

    return StreamingResponse(_gen(), media_type="application/x-ndjson")


@app.post("/api/projects/{project_id}/reset")
def api_reset_project(project_id: str) -> Dict[str, Any]:
    meta, _ = _get_or_scan_project(project_id)
    ws = Path(meta["workspace_path"])
    tpl = Path(meta["template_path"])
    if not tpl.exists():
        raise HTTPException(status_code=400, detail="Initial baseline snapshot unavailable for this project.")
    if ws.exists():
        shutil.rmtree(ws)
    shutil.copytree(tpl, ws)
    meta["adopted"] = False
    _persist_project_meta(project_id, meta)
    _STAGED_BUNDLES.pop(project_id, None)
    for sess in _PAIRING_SESSIONS.values():
        if sess.get("project_id") == project_id:
            sess["pending_files"] = {}
    _save_pairings_to_disk()
    report = scan_and_heal(ws, auto_heal=False)
    _PROJECT_REPORTS[project_id] = report
    return _serialize_project_detail(project_id, meta, report)


# ==================== NON-DESTRUCTIVE SURGICAL STAGING, USER ADOPTION & GITHUB PUSH ====================


def _serialize_staged_bundle(project_id: str, bundle: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "project_id": project_id,
        "adoptable_count": bundle["adoptable_count"],
        "untouched_safe_files": bundle["untouched_safe_files"],
        "touched_vulnerable_files": bundle["touched_vulnerable_files"],
        "avg_non_vulnerable_preservation_pct": bundle["avg_non_vulnerable_preservation_pct"],
        "proposals": bundle["proposals"],
        "staged_files": bundle["staged_files"],
        "original_files": bundle["original_files"],
    }


@app.post("/api/projects/{project_id}/propose-fixes")
def api_propose_fixes(project_id: str) -> Dict[str, Any]:
    """Compute surgical fixes in an isolated sandbox WITHOUT touching the project workspace."""
    meta, _ = _get_or_scan_project(project_id)
    ws = Path(meta["workspace_path"])
    bundle = stage_surgical_proposals(ws, allow_slm=True)
    _STAGED_BUNDLES[project_id] = bundle
    return _serialize_staged_bundle(project_id, bundle)


@app.post("/api/projects/{project_id}/propose-fixes-stream")
def api_propose_fixes_stream(project_id: str) -> StreamingResponse:
    """Stream NDJSON telemetry while staging surgical fixes in an isolated sandbox (0 workspace mutations)."""
    meta, _ = _get_or_scan_project(project_id)
    ws = Path(meta["workspace_path"])
    ev_queue: queue.Queue[Optional[Dict[str, Any]]] = queue.Queue()

    def _worker() -> None:
        try:
            bundle = stage_surgical_proposals(
                ws,
                allow_slm=True,
                on_event=lambda ev: ev_queue.put({"type": "progress", "event": ev}),
            )
            _STAGED_BUNDLES[project_id] = bundle
            ev_queue.put({"type": "complete", "payload": _serialize_staged_bundle(project_id, bundle)})
        except Exception as exc:
            ev_queue.put({"type": "error", "message": str(exc)})
        finally:
            ev_queue.put(None)

    threading.Thread(target=_worker, daemon=True).start()

    def _gen() -> Iterator[bytes]:
        while True:
            item = ev_queue.get()
            if item is None:
                break
            yield (json.dumps(item) + "\n").encode("utf-8")

    return StreamingResponse(_gen(), media_type="application/x-ndjson")


@app.post("/api/projects/{project_id}/adopt-fixes")
def api_adopt_fixes(project_id: str, req: AdoptFixesRequest) -> Dict[str, Any]:
    """Apply ONLY the user-approved surgical fixes after explicit user consent & queue Two-Way Sync to paired editors."""
    meta, _ = _get_or_scan_project(project_id)
    if not req.selected_finding_ids:
        raise HTTPException(status_code=400, detail="Select at least one surgical fix to adopt.")
    ws = Path(meta["workspace_path"])
    before_adopt_files = _read_workspace_files(ws, max_files=300)
    staged = _STAGED_BUNDLES.get(project_id)
    report = adopt_selected_proposals(
        ws,
        selected_finding_ids=req.selected_finding_ids,
        staged_bundle=staged,
        allow_slm=True,
    )
    meta["adopted"] = True
    _persist_project_meta(project_id, meta)
    _PROJECT_REPORTS[project_id] = report

    # Queue ONLY the newly modified surgical files for any Paired Local Editor sessions!
    after_adopt_files = _read_workspace_files(ws, max_files=300)
    delta_files = {
        rel: content
        for rel, content in after_adopt_files.items()
        if before_adopt_files.get(rel) != content
    }
    if delta_files:
        _load_pairings_from_disk()
        score_now = compute_security_score(report)
        open_now = report.summary.get("actionable_after", 0)
        for sess in _PAIRING_SESSIONS.values():
            if sess.get("project_id") == project_id:
                existing_pending = dict(sess.get("pending_files") or {})
                existing_pending.update(delta_files)
                sess["pending_files"] = existing_pending
                sess["ready_to_push"] = open_now == 0
                sess["security_score"] = score_now
                sess["open_threats"] = open_now
                sess["last_event"] = f"Web Studio approved {len(delta_files)} surgical file(s) -> queued for editor sync"
                sess["updated_at"] = time.time()
        _save_pairings_to_disk()

    return _serialize_project_detail(project_id, meta, report)


class GitHubTokenVerifyRequest(BaseModel):
    repo_url: str
    github_token: str
    save_if_valid: bool = True
    default_mode: str = "pull_request"
    base_branch: str = "main"


class OfflineGitPushRequest(BaseModel):
    repo_url: Optional[str] = None
    mode: str = "pull_request"
    base_branch: Optional[str] = None


def _resolve_effective_github_token(provided_token: str) -> str:
    t = (provided_token or "").strip()
    if t and t != "__SAVED__":
        return t
    saved = load_saved_github_config(include_raw_token=True)
    saved_tok = str(saved.get("github_token", "")).strip()
    if saved_tok:
        return saved_tok
    return discover_local_system_github_token()


@app.get("/api/github/config")
def api_get_github_config() -> Dict[str, Any]:
    """Return persisted GitHub connection configuration with masked token preview."""
    return load_saved_github_config(include_raw_token=False)


@app.delete("/api/github/config")
def api_delete_github_config() -> Dict[str, Any]:
    return clear_github_config()


@app.post("/api/github/verify-token")
@app.post("/api/github/config")
def api_verify_github_token(req: GitHubTokenVerifyRequest) -> Dict[str, Any]:
    """Pre-check GitHub PAT connectivity, authenticated account, and write permissions on target repo."""
    effective_tok = _resolve_effective_github_token(req.github_token)
    if not effective_tok:
        raise HTTPException(status_code=400, detail="Enter a GitHub Personal Access Token (`ghp_...` or `github_pat_...`).")
    try:
        verified = verify_github_token_access(repo_url=req.repo_url, github_token=effective_tok)
        if req.save_if_valid and verified.get("ok"):
            saved_cfg = save_github_config(
                repo_url=req.repo_url,
                github_token=effective_tok,
                default_mode=req.default_mode,
                base_branch=req.base_branch or str(verified.get("default_branch", "main")),
                authenticated_user=str(verified.get("authenticated_user", "")),
                token_kind=str(verified.get("token_kind", "")),
                write_verified=True,
            )
            verified["saved_config"] = saved_cfg
        return verified
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub API network error: {exc}")


@app.post("/api/projects/{project_id}/offline-git-push")
def api_project_offline_git_push(project_id: str, req: OfflineGitPushRequest) -> Dict[str, Any]:
    """Generate a compact ~4 KB 1-Paste Offline PowerShell 5.1 & Bash Git Push command (no PAT & no sandbox URL fetch)."""
    meta, _ = _get_or_scan_project(project_id)
    target_repo_url = (req.repo_url or meta.get("github_repo_url") or "").strip()
    if not target_repo_url:
        raise HTTPException(status_code=400, detail="Provide the target GitHub repository URL (`https://github.com/owner/repo`).")
    patch_resp = api_export_patch(project_id)
    patch_txt = bytes(patch_resp.body).decode("utf-8", errors="replace")
    if patch_txt.startswith("# No file differences"):
        raise HTTPException(status_code=400, detail="No adopted surgical fixes yet. Adopt fixes in Step 3 first.")
    try:
        return build_offline_git_push_commands(
            repo_url=target_repo_url,
            unified_patch=patch_txt,
            mode=req.mode,
            base_branch=req.base_branch or meta.get("github_branch") or "main",
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/projects/{project_id}/push-github")
def api_push_project_to_github(project_id: str, req: GitHubPushRequest) -> Dict[str, Any]:
    """Push ONLY the adopted surgical file modifications back to GitHub (Pull Request or Direct Commit)."""
    meta, _ = _get_or_scan_project(project_id)
    target_repo_url = (req.repo_url or meta.get("github_repo_url") or "").strip()
    if not target_repo_url:
        raise HTTPException(status_code=400, detail="Provide the target GitHub repository URL (`https://github.com/owner/repo`).")

    effective_tok = _resolve_effective_github_token(req.github_token)
    if not effective_tok:
        raise HTTPException(status_code=400, detail="Provide a GitHub Personal Access Token or use the 1-Paste Offline Git Push below.")

    ws = Path(meta["workspace_path"])
    tpl = Path(meta["template_path"])
    current_files = _read_workspace_files(ws, max_files=300)
    baseline_files = _read_workspace_files(tpl, max_files=300) if tpl.exists() else {}

    changed_only: Dict[str, str] = {
        rel: txt for rel, txt in current_files.items() if baseline_files.get(rel) != txt
    }
    if not changed_only:
        raise HTTPException(status_code=400, detail="No adopted code changes found yet. Adopt surgical fixes first.")

    try:
        result = push_surgical_fixes_to_github(
            repo_url=target_repo_url,
            github_token=effective_tok,
            changed_files=changed_only,
            mode=req.mode,
            base_branch=req.base_branch or meta.get("github_branch"),
            commit_message=req.commit_message,
            pr_title=req.pr_title,
        )
        return result
    except ValueError as exc:
        local_os_tok = discover_local_system_github_token()
        if local_os_tok and local_os_tok != effective_tok and "lacks write permission" in str(exc):
            try:
                return push_surgical_fixes_to_github(
                    repo_url=target_repo_url,
                    github_token=local_os_tok,
                    changed_files=changed_only,
                    mode=req.mode,
                    base_branch=req.base_branch or meta.get("github_branch"),
                    commit_message=req.commit_message,
                    pr_title=req.pr_title,
                )
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=str(exc))
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub API network error: {exc}")


@app.get("/api/projects/{project_id}/export/github-push-script")
def api_export_github_push_script(
    project_id: str,
    repo_url: Optional[str] = None,
    mode: str = "pull_request",
    base_branch: Optional[str] = None,
) -> Response:
    """Download a self-contained Zero-PAT Python script that pushes ONLY surgical files via local machine Git login."""
    meta, _ = _get_or_scan_project(project_id)
    target_repo_url = (repo_url or meta.get("github_repo_url") or "").strip()
    if not target_repo_url:
        raise HTTPException(status_code=400, detail="Provide the target GitHub repository URL first.")

    ws = Path(meta["workspace_path"])
    tpl = Path(meta["template_path"])
    current_files = _read_workspace_files(ws, max_files=300)
    baseline_files = _read_workspace_files(tpl, max_files=300) if tpl.exists() else {}
    changed_only = {rel: txt for rel, txt in current_files.items() if baseline_files.get(rel) != txt}
    if not changed_only:
        raise HTTPException(status_code=400, detail="Adopt surgical fixes in Step 3 before exporting the GitHub push script.")

    try:
        script_src = build_local_git_push_script(
            repo_url=target_repo_url,
            changed_files=changed_only,
            base_branch=(base_branch or meta.get("github_branch") or "main").strip(),
            mode=mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return Response(
        content=script_src.encode("utf-8"),
        media_type="text/x-python",
        headers={"Content-Disposition": 'attachment; filename="push_vibearmor_fixes.py"'},
    )


# ==================== MULTI-EDITOR EXTENSION MODULE (VS CODE / CURSOR / WINDSURF) ====================


def _build_readiness_checks(report: ScanAndHealReport) -> Dict[str, Dict[str, Any]]:
    active = (
        [f for f in report.findings_after if f.reachable and not f.requires_policy_spec]
        if report.mode == "auto_heal"
        else [f for f in report.findings_before if f.reachable and not f.requires_policy_spec]
    )
    env_c = sum(1 for f in active if f.rule_id in ("VA-ENV-001", "VA-ENV-002"))
    rls_c = sum(1 for f in active if f.pillar == Pillar.RLS_DPDP)
    key_c = sum(1 for f in active if f.pillar == Pillar.SECRET_BOUNDARY and f.rule_id not in ("VA-ENV-001", "VA-ENV-002"))
    inj_c = sum(1 for f in active if f.pillar == Pillar.TAINT_PAYMENT)
    sup_c = sum(1 for f in active if f.pillar == Pillar.SUPPLY_CHAIN)
    return {
        "dotenv_hygiene": {
            "passed": env_c == 0,
            "count": env_c,
            "label": ".env Variables & Gitignore Push Protection",
        },
        "supabase_rls": {
            "passed": rls_c == 0,
            "count": rls_c,
            "label": "Supabase / Postgres Row-Level Access Rules",
        },
        "browser_keys": {
            "passed": key_c == 0,
            "count": key_c,
            "label": "Browser React/Next Private API Key Isolation",
        },
        "injections_payments": {
            "passed": inj_c == 0,
            "count": inj_c,
            "label": "SQL/Code Injections & Payment Webhook Verification",
        },
        "supply_chain": {
            "passed": sup_c == 0,
            "count": sup_c,
            "label": "AI-Hallucinated Packages & Vulnerable Versions",
        },
    }


@app.get("/api/extension/status")
def api_extension_status() -> Dict[str, Any]:
    _ensure_default_projects()
    vsix_exists = VSIX_PACKAGE_PATH.exists()
    browser_exists = BROWSER_ZIP_PATH.exists()
    bridge_exists = BRIDGE_SCRIPT_PATH.exists()
    sessions_out = _serialize_pairing_sessions()
    return {
        "extension_name": "vibearmor-ide-guard",
        "version": "3.0.0",
        "vsix_ready": vsix_exists,
        "vsix_size_bytes": VSIX_PACKAGE_PATH.stat().st_size if vsix_exists else 0,
        "download_url": "/api/extension/download-vsix",
        "browser_ext_ready": browser_exists,
        "browser_ext_size_bytes": BROWSER_ZIP_PATH.stat().st_size if browser_exists else 0,
        "browser_download_url": "/api/extension/download-browser-zip",
        "bridge_ready": bridge_exists,
        "bridge_download_url": "/api/extension/download-bridge",
        "paired_sessions": sessions_out,
        "supported_editors": [
            {
                "id": "vscode",
                "name": "Visual Studio Code (Windows PowerShell)",
                "install_cmd": "code --install-extension \"$env:USERPROFILE\\Downloads\\vibearmor-guard-3.6.0.vsix\" --force",
            },
            {
                "id": "cursor",
                "name": "Cursor AI IDE (Windows PowerShell)",
                "install_cmd": "cursor --install-extension \"$env:USERPROFILE\\Downloads\\vibearmor-guard-3.6.0.vsix\" --force",
            },
            {
                "id": "macos_linux",
                "name": "VS Code / Cursor / Windsurf (macOS & Linux)",
                "install_cmd": "code --install-extension \"$HOME/Downloads/vibearmor-guard-3.6.0.vsix\" --force",
            },
            {
                "id": "gui_vsix",
                "name": "GUI Install (Inside VS Code / Cursor / Windsurf)",
                "install_cmd": "Ctrl+Shift+X (Extensions) -> '...' menu -> Install from VSIX -> Downloads/vibearmor-guard-3.6.0.vsix",
            },
            {
                "id": "any_editor_bridge",
                "name": "Two-Way Local Bridge (Windows `python` / macOS `python3`)",
                "install_cmd": "python vibearmor_bridge.py --token va_pair_xxxx --dir . --watch",
            },
        ],
        "recent_verifications": list(reversed(_EXTENSION_EVENTS[-15:])),
    }


def _serialize_pairing_sessions() -> List[Dict[str, Any]]:
    _load_pairings_from_disk()
    now = time.time()
    out: List[Dict[str, Any]] = []
    for tok, s in sorted(_PAIRING_SESSIONS.items(), key=lambda kv: kv[1].get("updated_at", 0), reverse=True):
        pending_map = s.get("pending_files") or {}
        out.append(
            {
                "pair_token": tok,
                "editor": s.get("editor", "Cursor"),
                "workspace_name": s.get("workspace_name", "workspace"),
                "local_path": s.get("local_path", "."),
                "branch": s.get("branch", "main"),
                "project_id": s.get("project_id"),
                "connected": bool(s.get("connected", False)),
                "ready_to_push": bool(s.get("ready_to_push", False)),
                "security_score": int(s.get("security_score", 0)),
                "open_threats": int(s.get("open_threats", 0)),
                "pending_fixes_count": len(pending_map),
                "pending_file_names": sorted(pending_map.keys()),
                "synced_fixes_total": int(s.get("synced_fixes_total", 0)),
                "last_event": s.get("last_event", "Awaiting editor sync"),
                "seconds_since_activity": max(0, int(now - float(s.get("updated_at", now)))),
            }
        )
    return out


@app.post("/api/extension/pair/create")
def api_pair_create(req: PairCreateRequest) -> Dict[str, Any]:
    """Generate a live Two-Way Pairing Token (`va_pair_...`) linking a local editor folder <-> Web Studio."""
    _ensure_default_projects()
    token = f"va_pair_{uuid.uuid4().hex[:12]}"
    linked_pid = req.project_id if req.project_id and req.project_id in _PROJECT_META else None
    ready = False
    score = 0
    open_cnt = 0
    ws_name = req.workspace_name.strip() or "local-editor-workspace"

    if linked_pid:
        meta, rep = _get_or_scan_project(linked_pid)
        ws_name = meta["name"]
        score = compute_security_score(rep)
        open_cnt = (
            rep.summary.get("actionable_after", 0)
            if rep.mode == "auto_heal"
            else rep.summary.get("actionable_before", 0)
        )
        ready = open_cnt == 0

    _PAIRING_SESSIONS[token] = {
        "pair_token": token,
        "editor": req.editor.strip() or "Cursor",
        "workspace_name": ws_name,
        "local_path": f"~/projects/{re.sub(r'[^a-zA-Z0-9._-]+', '-', ws_name)}",
        "branch": "main",
        "project_id": linked_pid,
        "connected": bool(linked_pid),
        "ready_to_push": ready,
        "security_score": score,
        "open_threats": open_cnt,
        "pending_files": {},
        "synced_fixes_total": 0,
        "last_event": (
            f"Paired with '{ws_name}' — Two-Way Editor <-> Web Studio Sync Ready"
            if linked_pid
            else "Token generated — run bridge or paste into IDE extension"
        ),
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    _save_pairings_to_disk()
    return _serialize_pairing_sessions()[0]


@app.get("/api/extension/pair/sessions")
def api_pair_list_sessions() -> Dict[str, Any]:
    _ensure_default_projects()
    return {"sessions": _serialize_pairing_sessions()}


@app.post("/api/extension/pair/sync-up")
def api_pair_sync_up(req: PairSyncUpRequest) -> Dict[str, Any]:
    """Receive source files from a paired Code Editor / Bridge, update live Paired Workspace & evaluate Hard Push Gate."""
    _ensure_default_projects()
    tok = req.pair_token.strip()
    if not tok.startswith("va_pair_"):
        raise HTTPException(status_code=400, detail="Invalid pairing token (must start with va_pair_).")

    sess = _PAIRING_SESSIONS.get(tok)
    pid = (sess or {}).get("project_id")
    if not pid or pid not in _PROJECT_META:
        safe_slug = re.sub(r"[^a-z0-9-]+", "-", req.workspace_name.lower()).strip("-")[:24] or "editor"
        pid = f"paired-{safe_slug}-{tok[-6:]}"

    proj_root = WORKSPACES_STORE / pid
    ws_dest = proj_root / "workspace"
    snap_dest = proj_root / "initial_snapshot"

    if pid != "vibebazaar-india":
        is_first_sync = not ws_dest.exists()
        if ws_dest.exists():
            shutil.rmtree(ws_dest)
        ws_dest.mkdir(parents=True, exist_ok=True)
        for item in req.files:
            rel = str(item.get("path", "")).lstrip("/").replace("..", "_")
            if not rel:
                continue
            target = (ws_dest / rel).resolve()
            if str(target).startswith(str(ws_dest.resolve())):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(str(item.get("content", "")), encoding="utf-8")
        if is_first_sync or not snap_dest.exists():
            shutil.rmtree(snap_dest, ignore_errors=True)
            shutil.copytree(ws_dest, snap_dest)

        meta = {
            "id": pid,
            "name": f"{req.workspace_name} ({req.editor})",
            "source_type": "editor-paired",
            "source_label": f"Paired {req.editor} · {req.local_path}",
            "github_branch": req.branch or "main",
            "adopted": False,
            "workspace_path": str(ws_dest),
            "template_path": str(snap_dest),
            "created_at": time.time(),
        }
        (proj_root / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        _PROJECT_META[pid] = meta
    else:
        meta = _PROJECT_META[pid]
        ws_dest = Path(meta["workspace_path"])

    _STAGED_BUNDLES.pop(pid, None)
    report = scan_and_heal(ws_dest, auto_heal=False)
    _PROJECT_REPORTS[pid] = report

    active_findings = [f for f in report.findings_before if f.reachable and not f.requires_policy_spec]
    score = compute_security_score(report)
    checks = _build_readiness_checks(report)
    ready = len(active_findings) == 0

    _PAIRING_SESSIONS[tok] = {
        **(sess or {}),
        "pair_token": tok,
        "editor": req.editor,
        "workspace_name": req.workspace_name,
        "local_path": req.local_path,
        "branch": req.branch,
        "project_id": pid,
        "connected": True,
        "ready_to_push": ready,
        "security_score": score,
        "open_threats": len(active_findings),
        "pending_files": (sess or {}).get("pending_files") or {},
        "synced_fixes_total": int((sess or {}).get("synced_fixes_total", 0)),
        "last_event": (
            f"Synced {len(req.files)} files from {req.editor} -> "
            + ("READY TO PUSH" if ready else f"BLOCKED ({len(active_findings)} threats)")
        ),
        "updated_at": time.time(),
    }
    _save_pairings_to_disk()

    return {
        "pair_token": tok,
        "project_id": pid,
        "ready_to_push": ready,
        "gate_verdict": "READY" if ready else "BLOCKED",
        "security_score": score,
        "open_threats": len(active_findings),
        "node_count": len(report.nodes),
        "edge_count": len(report.edges),
        "checks": checks,
        "findings": [f.model_dump(mode="json") for f in active_findings],
    }


@app.get("/api/extension/pair/{pair_token}/pending-fixes")
def api_pair_get_pending_fixes(pair_token: str) -> Dict[str, Any]:
    """Polled by the IDE Extension / Local Bridge to pull user-approved surgical fixes down to local disk."""
    _load_pairings_from_disk()
    sess = _PAIRING_SESSIONS.get(pair_token)
    if not sess:
        raise HTTPException(status_code=404, detail="Pairing session not found.")
    sess["updated_at"] = time.time()
    pending = sess.get("pending_files") or {}
    return {
        "pair_token": pair_token,
        "project_id": sess.get("project_id"),
        "pending_count": len(pending),
        "pending_files": pending,
    }


@app.post("/api/extension/pair/{pair_token}/ack-fixes")
def api_pair_ack_fixes(pair_token: str, req: PairAckFixesRequest) -> Dict[str, Any]:
    """Confirm that approved surgical fixes were written to the local editor folder."""
    _load_pairings_from_disk()
    sess = _PAIRING_SESSIONS.get(pair_token)
    if not sess:
        raise HTTPException(status_code=404, detail="Pairing session not found.")
    applied_cnt = len(req.applied_files) or len(sess.get("pending_files") or {})
    sess["pending_files"] = {}
    sess["synced_fixes_total"] = int(sess.get("synced_fixes_total", 0)) + applied_cnt
    sess["last_event"] = f"✓ Wrote {applied_cnt} surgical file(s) back to local {sess.get('editor', 'Editor')} folder"
    sess["updated_at"] = time.time()
    _save_pairings_to_disk()
    return {"acknowledged": True, "synced_fixes_total": sess["synced_fixes_total"]}


@app.post("/api/extension/browser/check-repo")
def api_browser_check_repo(req: BrowserRepoCheckRequest) -> Dict[str, Any]:
    """Used by the Chrome / Edge Browser Extension on GitHub Repo/PR pages & Vercel/Netlify/Render Deploy pages."""
    _ensure_default_projects()
    matched_pid: Optional[str] = None
    repo_slug = ""

    if req.repo_url.strip():
        _, repo_slug = _normalize_github_url(req.repo_url)
        for pid, meta in _PROJECT_META.items():
            if (meta.get("github_repo_url") or "").lower() == f"https://github.com/{repo_slug}".lower():
                matched_pid = pid
                break
        if not matched_pid and req.scan_if_missing:
            imported = api_import_github_repo(GitHubImportRequest(repo_url=f"https://github.com/{repo_slug}"))
            matched_pid = imported["project"]["id"]

    if not matched_pid and req.pair_token.strip() in _PAIRING_SESSIONS:
        matched_pid = _PAIRING_SESSIONS[req.pair_token.strip()].get("project_id")

    if not matched_pid:
        # Fallback to most recently imported non-reference workspace if user is on Vercel/Netlify/Render
        non_ref = [pid for pid, m in _PROJECT_META.items() if m.get("source_type") != "reference"]
        if non_ref and req.page_host and req.page_host != "github.com":
            matched_pid = non_ref[-1]

    if not matched_pid or matched_pid not in _PROJECT_META:
        return {
            "audited": False,
            "repo_slug": repo_slug,
            "ready_to_push": False,
            "security_score": 0,
            "open_threats": 0,
            "project_id": None,
            "checks": {},
            "top_findings": [],
        }

    meta, report = _get_or_scan_project(matched_pid)
    active_findings = (
        [f for f in report.findings_after if f.reachable and not f.requires_policy_spec]
        if report.mode == "auto_heal"
        else [f for f in report.findings_before if f.reachable and not f.requires_policy_spec]
    )
    score = compute_security_score(report)
    ready = len(active_findings) == 0
    checks = _build_readiness_checks(report)

    _EXTENSION_EVENTS.append(
        {
            "session_id": f"brw-{uuid.uuid4().hex[:6]}",
            "timestamp": time.strftime("%H:%M:%S UTC", time.gmtime()),
            "editor": f"Browser Guard ({req.page_host or 'Chrome'})",
            "workspace_name": meta["name"],
            "branch": meta.get("github_branch") or "main",
            "ready_to_push": ready,
            "ready_to_deploy": ready,
            "blocking_count": len(active_findings),
            "security_score": score,
        }
    )

    return {
        "audited": True,
        "project_id": matched_pid,
        "repo_slug": repo_slug or meta["name"],
        "ready_to_push": ready,
        "gate_verdict": "READY" if ready else "BLOCKED",
        "security_score": score,
        "open_threats": len(active_findings),
        "checks": checks,
        "top_findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": f.title,
                "file_path": f.file_path,
                "line_start": f.line_start,
            }
            for f in active_findings[:8]
        ],
    }


@app.get("/api/extension/download-vsix")
@app.get("/api/extension/download/vsix")
def api_download_vsix() -> FileResponse:
    if not VSIX_PACKAGE_PATH.exists():
        raise HTTPException(status_code=404, detail="VSIX extension package not built yet.")
    return FileResponse(
        str(VSIX_PACKAGE_PATH),
        media_type="application/octet-stream",
        filename="vibearmor-guard-3.6.0.vsix",
    )


@app.get("/api/extension/download-browser-zip")
@app.get("/api/extension/download/browser-zip")
def api_download_browser_zip() -> FileResponse:
    if not BROWSER_ZIP_PATH.exists():
        raise HTTPException(status_code=404, detail="Browser extension archive not built yet.")
    return FileResponse(
        str(BROWSER_ZIP_PATH),
        media_type="application/zip",
        filename="vibearmor-browser-guard-3.0.0.zip",
    )


@app.get("/api/extension/download-bridge")
@app.get("/api/extension/download/bridge-script")
def api_download_bridge_script() -> FileResponse:
    if not BRIDGE_SCRIPT_PATH.exists():
        raise HTTPException(status_code=404, detail="Bridge script not found.")
    return FileResponse(
        str(BRIDGE_SCRIPT_PATH),
        media_type="text/x-python; charset=utf-8",
        filename="vibearmor_bridge.py",
    )


@app.post("/api/extension/verify-readiness")
def api_extension_verify_readiness(req: ExtensionVerifyRequest) -> Dict[str, Any]:
    """Endpoint called by VS Code / Cursor / Windsurf Extension before GitHub Push or Cloud Deploy."""
    session_id = f"ext-{uuid.uuid4().hex[:8]}"

    if req.project_id:
        meta, report = _get_or_scan_project(req.project_id)
        ws = Path(meta["workspace_path"])
        ws_name = meta["name"]
        if not req.include_proposals or report.mode == "auto_heal":
            proposals = []
        else:
            cached_b = _STAGED_BUNDLES.get(req.project_id)
            if not cached_b:
                cached_b = stage_surgical_proposals(ws, allow_slm=True)
                _STAGED_BUNDLES[req.project_id] = cached_b
            proposals = cached_b["proposals"]
    else:
        if not req.files:
            raise HTTPException(status_code=400, detail="Provide workspace files or project_id.")
        ws_name = req.workspace_name
        with tempfile.TemporaryDirectory(prefix="vibearmor_ext_") as tmp:
            root = Path(tmp)
            for f in req.files:
                rel = str(f.get("path", "")).lstrip("/").replace("..", "_")
                if not rel:
                    continue
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(str(f.get("content", "")), encoding="utf-8")
            report = scan_and_heal(root, auto_heal=False)
            proposals = stage_surgical_proposals(root, allow_slm=True)["proposals"] if req.include_proposals else []

    active_findings = (
        [f for f in report.findings_after if f.reachable and not f.requires_policy_spec]
        if report.mode == "auto_heal"
        else [f for f in report.findings_before if f.reachable and not f.requires_policy_spec]
    )
    score = compute_security_score(report)
    checks = _build_readiness_checks(report)
    ready = len(active_findings) == 0

    event_record = {
        "session_id": session_id,
        "timestamp": time.strftime("%H:%M:%S UTC", time.gmtime()),
        "editor": req.editor,
        "workspace_name": ws_name,
        "branch": req.branch,
        "ready_to_push": ready,
        "ready_to_deploy": ready,
        "blocking_count": len(active_findings),
        "security_score": score,
    }
    _EXTENSION_EVENTS.append(event_record)
    if len(_EXTENSION_EVENTS) > 30:
        del _EXTENSION_EVENTS[:-30]

    return {
        **event_record,
        "project_id": req.project_id,
        "node_count": len(report.nodes),
        "edge_count": len(report.edges),
        "checks": checks,
        "scan_latency_ms": report.scan_latency_ms,
        "findings": [f.model_dump(mode="json") for f in active_findings],
        "proposals": proposals,
    }


@app.get("/api/projects/{project_id}/export/patch")
def api_export_patch(project_id: str) -> Response:
    import difflib as _difflib
    meta, report = _get_or_scan_project(project_id)
    if report.patches:
        patch_txt = build_git_patch(report.patches)
    else:
        ws = Path(meta["workspace_path"])
        tpl = Path(meta["template_path"])
        cur_map = _read_workspace_files(ws, max_files=300)
        base_map = _read_workspace_files(tpl, max_files=300) if tpl.exists() else {}
        chunks: List[str] = []
        for rel_p in sorted(set(cur_map.keys()) | set(base_map.keys())):
            if rel_p.split("/")[-1] in {".env", ".env.local"}:
                continue
            b_txt = base_map.get(rel_p, "")
            a_txt = cur_map.get(rel_p, "")
            if b_txt != a_txt:
                is_added = rel_p not in base_map and not b_txt
                hdr = f"diff --git a/{rel_p} b/{rel_p}\n" + ("new file mode 100644\n" if is_added else "")
                chunks.append(
                    hdr
                    + "".join(
                        _difflib.unified_diff(
                            b_txt.splitlines(keepends=True),
                            a_txt.splitlines(keepends=True),
                            fromfile="/dev/null" if is_added else f"a/{rel_p}",
                            tofile=f"b/{rel_p}",
                        )
                    )
                )
        patch_txt = "\n".join(chunks) if chunks else "# No file differences yet — adopt surgical fixes in Step 3 first.\n"
    return Response(
        content=patch_txt,
        media_type="text/x-diff; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="vibearmor-{project_id}.patch"'},
    )


@app.get("/api/projects/{project_id}/export/zip")
def api_export_zip(project_id: str) -> Response:
    meta, _ = _get_or_scan_project(project_id)
    zip_bytes = build_workspace_zip(Path(meta["workspace_path"]))
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{project_id}-healed.zip"'},
    )


@app.get("/api/projects/{project_id}/export/certificate")
def api_export_certificate(project_id: str) -> HTMLResponse:
    meta, report = _get_or_scan_project(project_id)
    digest = compute_workspace_digest(Path(meta["workspace_path"]))
    cert_html = build_audit_certificate_html(meta["name"], report, digest)
    return HTMLResponse(content=cert_html)


class StageExportRequest(BaseModel):
    artifact_kind: str  # "vsix" | "browser_zip" | "bridge_py" | "project_zip" | "project_patch" | "project_cert" | "github_push_script"
    project_id: Optional[str] = None
    repo_url: Optional[str] = None
    mode: str = "pull_request"
    base_branch: Optional[str] = None


@app.post("/api/exports/stage")
def api_stage_export_to_workspace(req: StageExportRequest) -> Dict[str, Any]:
    """Save any extension/project deliverable into `/home/user/exports/` AND return inline preview/install metadata."""
    export_dir = Path("/home/user/exports")
    export_dir.mkdir(parents=True, exist_ok=True)

    kind = req.artifact_kind
    raw_bytes: bytes = b""
    filename = "artifact.bin"
    download_path = ""
    is_text = False
    is_html = False

    if kind == "vsix":
        if not VSIX_PACKAGE_PATH.exists():
            raise HTTPException(status_code=404, detail="VSIX package not found.")
        raw_bytes = VSIX_PACKAGE_PATH.read_bytes()
        filename = "vibearmor-guard-3.6.0.vsix"
        download_path = "/api/extension/download-vsix"
    elif kind == "browser_zip":
        if not BROWSER_ZIP_PATH.exists():
            raise HTTPException(status_code=404, detail="Browser extension zip not found.")
        raw_bytes = BROWSER_ZIP_PATH.read_bytes()
        filename = "vibearmor-browser-guard-3.0.0.zip"
        download_path = "/api/extension/download-browser-zip"
    elif kind == "bridge_py":
        if not BRIDGE_SCRIPT_PATH.exists():
            raise HTTPException(status_code=404, detail="Bridge script not found.")
        raw_bytes = BRIDGE_SCRIPT_PATH.read_bytes()
        filename = "vibearmor_bridge.py"
        download_path = "/api/extension/download-bridge"
        is_text = True
    elif kind in ("project_zip", "project_patch", "project_cert", "github_push_script"):
        if not req.project_id:
            raise HTTPException(status_code=400, detail="project_id is required.")
        pid = req.project_id
        meta, report = _get_or_scan_project(pid)
        safe_slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", meta["name"]).strip("-") or pid
        if kind == "project_zip":
            raw_bytes = build_workspace_zip(Path(meta["workspace_path"]))
            filename = f"{safe_slug}-vibearmor-updated.zip"
            download_path = f"/api/projects/{pid}/export/zip"
        elif kind == "project_patch":
            resp_p = api_export_patch(pid)
            raw_bytes = bytes(resp_p.body)
            filename = f"{safe_slug}-vibearmor.patch"
            download_path = f"/api/projects/{pid}/export/patch"
            is_text = True
        elif kind == "project_cert":
            digest = compute_workspace_digest(Path(meta["workspace_path"]))
            html_str = build_audit_certificate_html(meta["name"], report, digest)
            raw_bytes = html_str.encode("utf-8")
            filename = f"{safe_slug}-audit-report.html"
            download_path = f"/api/projects/{pid}/export/certificate"
            is_text = True
            is_html = True
        elif kind == "github_push_script":
            resp_s = api_export_github_push_script(
                project_id=pid,
                repo_url=req.repo_url,
                mode=req.mode,
                base_branch=req.base_branch,
            )
            raw_bytes = bytes(resp_s.body)
            filename = f"push_{safe_slug}_fixes.py"
            q_repo = req.repo_url or meta.get("github_repo_url") or ""
            download_path = f"/api/projects/{pid}/export/github-push-script?repo_url={q_repo}&mode={req.mode}"
            is_text = True
    else:
        raise HTTPException(status_code=400, detail=f"Unknown artifact_kind: {kind}")

    dest_file = export_dir / filename
    dest_file.write_bytes(raw_bytes)
    text_content = raw_bytes.decode("utf-8", errors="replace") if is_text else None

    # Build 100% Offline Self-Contained PowerShell 5.1/7 & Bash Installers (Zero HTTP fetch, Zero '&&', writes to $HOME\Downloads)
    import base64 as _b64
    import gzip as _gzip

    offline_ps_cmd: Optional[str] = None
    offline_sh_cmd: Optional[str] = None

    if kind == "vsix":
        b64_raw = _b64.b64encode(raw_bytes).decode("ascii")
        offline_ps_cmd = (
            f"$out=Join-Path $env:USERPROFILE 'Downloads\\{filename}'; "
            f"[IO.File]::WriteAllBytes($out,[Convert]::FromBase64String('{b64_raw}')); "
            f"Write-Host ('Saved VSIX v3.6.0 to '+$out) -ForegroundColor Green; "
            f"Remove-Item -Recurse -Force \"$env:USERPROFILE\\.vscode\\extensions\\nexgen-coders.vibearmor-ide-guard-3.0*\" -ErrorAction SilentlyContinue; "
            f"Remove-Item -Recurse -Force \"$env:USERPROFILE\\.vscode\\extensions\\nexgen-coders.vibearmor-ide-guard-3.5*\" -ErrorAction SilentlyContinue; "
            f"$installed=$false; "
            f"$eds=@(@('code',\"$env:LOCALAPPDATA\\Programs\\Microsoft VS Code\\bin\\code.cmd\"),@('cursor',\"$env:LOCALAPPDATA\\Programs\\cursor\\resources\\app\\bin\\cursor.cmd\"),@('windsurf')); "
            f"foreach($grp in $eds){{ foreach($c in $grp){{ "
            f"if(Get-Command $c -ErrorAction SilentlyContinue){{ & $c --install-extension $out --force; $installed=$true; break }} "
            f"elseif(Test-Path $c){{ & $c --install-extension $out --force; $installed=$true; break }} "
            f"}} }}; "
            f"if(-not $installed){{ Write-Host ('Open VS Code/Cursor -> Extensions -> ... -> Install from VSIX -> select '+$out) -ForegroundColor Yellow }} "
            f"else {{ Write-Host 'IMPORTANT: In VS Code/Cursor press Ctrl+Shift+P -> Developer: Reload Window so VS Code v3.6 activates!' -ForegroundColor Cyan }}"
        )
        offline_sh_cmd = (
            f"OUT=\"$HOME/Downloads/{filename}\"; mkdir -p \"$HOME/Downloads\"; "
            f"python3 -c \"import base64,pathlib; pathlib.Path('$OUT').write_bytes(base64.b64decode('{b64_raw}'))\"; "
            f"for c in cursor code windsurf; do command -v $c >/dev/null 2>&1 && $c --install-extension \"$OUT\" --force; done; "
            f"echo \"Saved & installed $OUT — Reload Window in VS Code/Cursor!\""
        )
    elif kind == "browser_zip":
        b64_raw = _b64.b64encode(raw_bytes).decode("ascii")
        offline_ps_cmd = (
            f"$zf=Join-Path $env:USERPROFILE 'Downloads\\{filename}'; "
            f"$dest=Join-Path $env:USERPROFILE 'Downloads\\vibearmor-browser-guard'; "
            f"[IO.File]::WriteAllBytes($zf,[Convert]::FromBase64String('{b64_raw}')); "
            f"Expand-Archive -Force -Path $zf -DestinationPath $dest; "
            f"Write-Host ('Extracted Chrome/Edge Extension to: '+$dest) -ForegroundColor Green; "
            f"Write-Host 'Next: Open chrome://extensions -> Developer mode ON -> Load unpacked -> select the folder above!' -ForegroundColor Cyan"
        )
        offline_sh_cmd = (
            f"ZF=\"$HOME/Downloads/{filename}\"; DEST=\"$HOME/Downloads/vibearmor-browser-guard\"; mkdir -p \"$DEST\"; "
            f"python3 -c \"import base64,zipfile,io; z=zipfile.ZipFile(io.BytesIO(base64.b64decode('{b64_raw}'))); z.extractall('$DEST')\"; "
            f"echo \"Extracted Chrome/Edge Extension to $DEST — Load unpacked in chrome://extensions\""
        )
    elif kind == "bridge_py":
        gz_b64 = _b64.b64encode(_gzip.compress(raw_bytes, compresslevel=9)).decode("ascii")
        offline_ps_cmd = (
            f"$ms=New-Object IO.MemoryStream(,[Convert]::FromBase64String('{gz_b64}')); "
            f"$gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); "
            f"$out=Join-Path (Get-Location) 'vibearmor_bridge.py'; "
            f"$fs=[IO.File]::Create($out); $gz.CopyTo($fs); $fs.Close(); $gz.Close(); "
            f"Write-Host ('Saved '+$out) -ForegroundColor Green; python $out --help"
        )
        offline_sh_cmd = (
            f"python3 -c \"import base64,gzip,pathlib; pathlib.Path('vibearmor_bridge.py').write_bytes(gzip.decompress(base64.b64decode('{gz_b64}')))\"; "
            f"python3 vibearmor_bridge.py --help"
        )
    elif kind == "github_push_script" and req.project_id:
        meta_g, _ = _get_or_scan_project(req.project_id)
        target_r = (req.repo_url or meta_g.get("github_repo_url") or "").strip()
        p_resp = api_export_patch(req.project_id)
        p_txt = bytes(p_resp.body).decode("utf-8", errors="replace")
        if target_r and not p_txt.startswith("# No file differences"):
            try:
                offline_cmds = build_offline_git_push_commands(
                    repo_url=target_r,
                    unified_patch=p_txt,
                    mode=req.mode,
                    base_branch=req.base_branch or meta_g.get("github_branch") or "main",
                )
                offline_ps_cmd = offline_cmds["powershell_cmd"]
                offline_sh_cmd = offline_cmds["bash_cmd"]
            except Exception:
                pass

    return {
        "ok": True,
        "artifact_kind": kind,
        "filename": filename,
        "size_bytes": len(raw_bytes),
        "saved_workspace_path": f"exports/{filename}",
        "download_path": download_path,
        "offline_powershell_cmd": offline_ps_cmd,
        "offline_bash_cmd": offline_sh_cmd,
        "is_text": is_text,
        "is_html": is_html,
        "text_content": text_content,
    }


# ==================== EVIDENCE-DRIVEN AGENTIC SECURITY, RAG & POLICY ====================


class RagSearchRequest(BaseModel):
    query: str
    cwe_hint: str = ""
    rule_id_hint: str = ""
    top_k: int = 3


@app.get("/api/projects/{project_id}/evidence")
def api_get_project_evidence(project_id: str) -> Dict[str, Any]:
    """Return full Control Center, Security Evidence Packages (FAISS RAG), 12-Node Evidence Graphs & Policy Verdict."""
    meta, report = _get_or_scan_project(project_id)
    return build_workspace_evidence_bundle(
        project_id=project_id,
        project_name=meta["name"],
        workspace_path=Path(meta["workspace_path"]),
        report=report,
    )


@app.post("/api/projects/{project_id}/agentic-run")
def api_run_project_langgraph_workflow(project_id: str) -> Dict[str, Any]:
    """Execute the stateful 4-Agent LangGraph security pipeline across active workspace findings."""
    meta, _ = _get_or_scan_project(project_id)
    return run_agentic_security_workflow_on_workspace(Path(meta["workspace_path"]))


@app.post("/api/rag/search")
def api_search_security_rag(req: RagSearchRequest) -> Dict[str, Any]:
    """Query VibeArmor's FAISS Security RAG Knowledge Base directly (CWE, OWASP, CAPEC, Verified Patterns)."""
    return search_security_knowledge_base(
        query=req.query,
        cwe_hint=req.cwe_hint,
        rule_id_hint=req.rule_id_hint,
        top_k=max(1, min(req.top_k, 10)),
    )


@app.get("/api/policy")
def api_get_security_policy() -> Dict[str, Any]:
    return {"security": load_security_policy().model_dump()}


@app.post("/api/policy")
def api_update_security_policy(cfg: SecurityPolicyConfig) -> Dict[str, Any]:
    save_security_policy(cfg)
    return {"ok": True, "security": cfg.model_dump()}


# ==================== LIVE EXPLOIT LAB & SUPABASE AUDITOR ====================


@app.post("/api/projects/{project_id}/exploit")
def api_project_custom_exploit(project_id: str, req: ExploitProbeRequest) -> Dict[str, Any]:
    """Execute custom live red-team probes against the currently active workspace."""
    meta, report = _get_or_scan_project(project_id)
    return execute_workspace_exploit_suite(
        pid=project_id,
        ws=Path(meta["workspace_path"]),
        report=report,
        sqli_payload=req.sqli_payload,
        caller_role=req.caller_role,
        caller_uid=req.caller_uid,
        razorpay_order_id=req.razorpay_order_id,
        razorpay_payment_id=req.razorpay_payment_id,
        razorpay_signature=req.razorpay_signature,
    )


@app.post("/api/projects/{project_id}/supabase-sql-audit")
def api_project_supabase_sql_audit(project_id: str) -> Dict[str, Any]:
    """Run a structured PostgreSQL/Supabase RLS & DPDP table exposure audit on the active workspace's SQL schema."""
    from core.graph.sql_rls_parser import parse_sql_files
    t0 = time.perf_counter()
    meta, _ = _get_or_scan_project(project_id)
    ws = Path(meta["workspace_path"])
    sql_files = [
        (str(p.relative_to(ws)).replace("\\", "/"), p.read_text(encoding="utf-8", errors="ignore"))
        for p in sorted(ws.rglob("*.sql"))
        if ".vibearmor" not in p.parts
    ]
    sql_res = parse_sql_files(sql_files)
    audited_tables: List[Dict[str, Any]] = []
    rec_sql: List[str] = []

    for tname, tbl in sorted(sql_res.tables.items()):
        cols = list(tbl.columns.keys())
        pii_cols = list(tbl.dpdp_pii_columns)
        has_vacuous = any(p.is_vacuous_true for p in tbl.policies)
        unprotected = (not tbl.rls_enabled) or (len(tbl.policies) == 0) or has_vacuous
        risk = "SAFE"
        if not tbl.rls_enabled or len(tbl.policies) == 0:
            risk = "CRITICAL_NO_RLS"
        elif has_vacuous:
            risk = "CRITICAL_VACUOUS_RLS"
        if unprotected:
            guard = f"((select auth.uid()) = {tbl.owner_column})" if tbl.owner_column else "((select auth.uid()) IS NOT NULL)"
            rec_sql.append(
                f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY;\n"
                f'CREATE POLICY "vibearmor_{tname}_iso" ON public.{tname} FOR ALL TO authenticated USING ({guard}) WITH CHECK ({guard});'
            )
        audited_tables.append(
            {
                "table": tname,
                "columns": cols[:12],
                "dpdp_pii_columns": pii_cols,
                "owner_column": tbl.owner_column,
                "anon_endpoint_open": unprotected,
                "anon_rows_visible": 1 if unprotected else 0,
                "risk": risk,
            }
        )

    return {
        "supabase_url": f"workspace://{meta['name']} ({len(sql_files)} SQL migration file(s))",
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        "tables_discovered": len(audited_tables),
        "tables": audited_tables,
        "recommended_rls_migration": (
            "\n\n".join(rec_sql)
            if rec_sql
            else "-- All SQL tables in this workspace enforce non-vacuous Row-Level Security!"
        ),
    }


@app.post("/api/demo/exploit")
def api_demo_custom_exploit(req: ExploitProbeRequest) -> Dict[str, Any]:
    _ensure_default_projects()
    return execute_live_exploit_suite(
        DEMO_WORKSPACE_DIR,
        sqli_payload=req.sqli_payload,
        caller_role=req.caller_role,
        caller_uid=req.caller_uid,
        razorpay_order_id=req.razorpay_order_id,
        razorpay_payment_id=req.razorpay_payment_id,
        razorpay_signature=req.razorpay_signature,
    )


@app.post("/api/supabase-live/audit")
def api_supabase_live_audit(req: SupabaseLiveAuditRequest) -> Dict[str, Any]:
    """Read-only live Supabase PostgREST OpenAPI exposure auditor (zero mutations)."""
    base_url = req.supabase_url.strip().rstrip("/")
    key = req.anon_key.strip()
    if not base_url.startswith("https://") or ".supabase.co" not in base_url:
        raise HTTPException(status_code=400, detail="Enter a valid https://<project-ref>.supabase.co URL.")
    if len(key) < 20:
        raise HTTPException(status_code=400, detail="Provide a valid Supabase anon / publishable API key.")

    headers = {"apikey": key, "Authorization": f"Bearer {key}"}
    t0 = time.perf_counter()
    try:
        resp = httpx.get(f"{base_url}/rest/v1/", headers=headers, timeout=8.0)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Supabase PostgREST endpoint: {exc}")

    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail=f"PostgREST returned HTTP {resp.status_code}. Check URL and anon key.")

    spec = resp.json()
    definitions = spec.get("definitions", {}) or {}
    audited_tables: List[Dict[str, Any]] = []
    generated_sql: List[str] = []

    for tname, schema_def in list(definitions.items())[:25]:
        props: Dict[str, Any] = schema_def.get("properties", {}) or {}
        cols = list(props.keys())
        pii_cols = [c for c in cols if c.lower() in DPDP_PII_PATTERNS or any(p in c.lower() for p in ("phone", "pan", "aadhaar", "email", "address"))]
        owner_col = next((c for c in ("user_id", "owner_id", "customer_id", "author_id", "profile_id") if c in cols), None)

        # Safe read-only `limit=1` probe to check if anon receives 200 with data
        anon_readable = False
        sample_count = 0
        try:
            r_tbl = httpx.get(f"{base_url}/rest/v1/{tname}?select=*&limit=2", headers=headers, timeout=4.0)
            if r_tbl.status_code == 200 and isinstance(r_tbl.json(), list):
                anon_readable = True
                sample_count = len(r_tbl.json())
        except Exception:
            pass

        risk = "SAFE"
        if anon_readable and sample_count > 0 and pii_cols:
            risk = "CRITICAL"
        elif anon_readable and pii_cols:
            risk = "HIGH"
        elif anon_readable and owner_col:
            risk = "MEDIUM"

        if risk in ("CRITICAL", "HIGH", "MEDIUM"):
            guard = f"((select auth.uid()) = {owner_col})" if owner_col else "((select auth.uid()) IS NOT NULL)"
            generated_sql.append(
                f"ALTER TABLE public.{tname} ENABLE ROW LEVEL SECURITY;\n"
                f'CREATE POLICY "vibearmor_{tname}_iso" ON public.{tname} FOR ALL TO authenticated USING ({guard}) WITH CHECK ({guard});'
            )

        audited_tables.append(
            {
                "table": tname,
                "columns": cols[:12],
                "dpdp_pii_columns": pii_cols,
                "owner_column": owner_col,
                "anon_endpoint_open": anon_readable,
                "anon_rows_visible": sample_count,
                "risk": risk,
            }
        )

    return {
        "supabase_url": base_url,
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        "tables_discovered": len(audited_tables),
        "tables": audited_tables,
        "recommended_rls_migration": "\n\n".join(generated_sql) if generated_sql else "-- All inspected PostgREST endpoints appear restricted.",
    }


# ==================== BACKWARDS-COMPATIBLE ENDPOINTS ====================


@app.get("/api/health")
def api_health() -> Dict[str, Any]:
    _ensure_default_projects()
    return {
        "status": "ok",
        "engine": "VibeArmor v2.0",
        "team": "NeXGen Coder's (Syed Suhail, Alam Nawaz Sha, Vivek Gowda)",
        "slm": get_slm_status(),
        "demo_workspace_ready": DEMO_WORKSPACE_DIR.exists(),
        "eval_results_ready": EVAL_RESULTS_PATH.exists(),
    }


@app.get("/api/demo/state")
def api_demo_state() -> Dict[str, Any]:
    meta, report = _get_or_scan_project("vibebazaar-india")
    return _serialize_project_detail("vibebazaar-india", meta, report)


@app.post("/api/demo/breach")
def api_demo_breach() -> Dict[str, Any]:
    _ensure_default_projects()
    return execute_live_exploit_suite(DEMO_WORKSPACE_DIR)


@app.post("/api/demo/heal")
def api_demo_heal() -> Dict[str, Any]:
    detail = api_heal_project("vibebazaar-india")
    detail["breach_after"] = detail["breach"]
    return detail


@app.post("/api/demo/reset")
def api_demo_reset() -> Dict[str, Any]:
    detail = api_reset_project("vibebazaar-india")
    detail["status"] = "reset_complete"
    return detail


@app.post("/api/sandbox/analyze")
def api_sandbox_analyze(req: SandboxRequest) -> Dict[str, Any]:
    if not req.files:
        raise HTTPException(status_code=400, detail="Provide at least one file to analyze.")
    with tempfile.TemporaryDirectory(prefix="vibearmor_sandbox_") as tmp:
        root = Path(tmp)
        for sf in req.files:
            clean_rel = sf.path.lstrip("/").replace("..", "_")
            dest = root / clean_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(sf.content, encoding="utf-8")

        report = scan_and_heal(root, auto_heal=req.auto_heal, allow_slm=req.allow_slm)
        after_files = _read_workspace_files(root)
        return {
            "report": report.model_dump(),
            "after_files": after_files,
            "git_patch": build_git_patch(report.patches),
            "security_score": compute_security_score(report),
        }


@app.get("/api/eval/results")
def api_eval_results() -> JSONResponse:
    if not EVAL_RESULTS_PATH.exists():
        raise HTTPException(status_code=404, detail="Benchmark results not generated yet.")
    data = json.loads(EVAL_RESULTS_PATH.read_text(encoding="utf-8"))
    return JSONResponse(content=data)


# Mount compiled VibeArmor Studio SPA
if (STATIC_UI_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_UI_DIR / "assets")), name="studio-assets")


@app.api_route("/{full_path:path}", methods=["GET", "HEAD"], include_in_schema=False)
def serve_studio_spa(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API route not found")
    candidate = STATIC_UI_DIR / full_path
    if full_path and candidate.exists() and candidate.is_file():
        return FileResponse(str(candidate))
    index_html = STATIC_UI_DIR / "index.html"
    if index_html.exists():
        return FileResponse(str(index_html))
    return JSONResponse({"message": "VibeArmor API v2.0 running.", "docs": "/docs"})
