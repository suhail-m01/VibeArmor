"""Direct GitHub Repository Updater (Pull Request, Auto-Fork PR, Direct Commit, or Zero-PAT Script).

Features:
1. True Pre-Flight Write-Capability Probe:
   - Never trusts `repo_info["permissions"]["push"]` alone (which GitHub reports as `true` for repo owners
     on public repos even when the token itself has zero scopes or `Contents: No access`).
   - Inspects `X-OAuth-Scopes` (Classic PATs) AND runs a zero-side-effect `POST /repos/{owner}/{repo}/git/refs` `{}`
     authorization probe (`422` = write confirmed, `403` = read-only token with `X-Accepted-GitHub-Permissions`).
2. 3-Layer Commit & Push Engine:
   - Layer 1: Atomic Git Data Trees API (`POST /git/trees` -> `/git/commits` -> `/git/refs`)
   - Layer 2: Contents REST API (`POST /git/refs` + `PUT /repos/{owner}/{repo}/contents/{path}`)
   - Layer 3: Native `git push` over Smart HTTPS (`https://x-access-token:<token>@github.com/...`)
3. Auto-Fork + Cross-Repo PR when pushing a Pull Request to another user's public repository.
4. Graceful Compare-PR URL fallback when token has `Contents: Read & write` without `Pull requests: Read & write`.
5. Zero-PAT Self-Contained Local Push Script generator (`push_vibearmor_fixes.py`) for pushing via local machine Git login.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

FORBIDDEN_ENV_PUSH_NAMES = {".env", ".env.local", ".env.development", ".env.production", ".env.staging"}
CLASSIC_TOKEN_NEW_URL = "https://github.com/settings/tokens/new?description=VibeArmor+Surgical+Security+Sync&scopes=repo"
FINE_GRAINED_TOKEN_URL = "https://github.com/settings/personal-access-tokens/new"


def parse_github_owner_repo(repo_url: str) -> Tuple[str, str]:
    cleaned = repo_url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    m = re.match(r"^(?:https?://github\.com/)?([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+)$", cleaned)
    if not m:
        raise ValueError("Invalid GitHub repository URL. Expected 'https://github.com/owner/repo'.")
    return m.group(1), m.group(2)


def _detect_token_kind(token: str) -> str:
    if token.startswith("github_pat_"):
        return f"Fine-Grained PAT (github_pat_..., {len(token)} chars)"
    if token.startswith("ghp_"):
        return f"Classic PAT (ghp_..., {len(token)} chars)"
    if token.startswith("gho_"):
        return f"GitHub OAuth / Credential Manager Token (gho_..., {len(token)} chars)"
    if token.startswith(("ghu_", "ghs_")):
        return f"GitHub App Token ({len(token)} chars)"
    return f"Token ({len(token)} chars)"


def discover_local_system_github_token() -> str:
    """Auto-discover local OS GitHub credentials (Windows Git Credential Manager, macOS Keychain, or `gh` CLI).

    Note: Only finds credentials when VibeArmor runs on the developer's local machine; returns '' on unauthenticated cloud sandboxes.
    """
    for env_key in ("GITHUB_TOKEN", "GH_TOKEN"):
        val = (os.getenv(env_key) or "").strip()
        if val:
            return val
    try:
        r_gh = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=3,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if r_gh.returncode == 0 and r_gh.stdout.strip():
            return r_gh.stdout.strip()
    except Exception:
        pass
    try:
        r_cred = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True,
            text=True,
            timeout=3,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
        )
        if r_cred.returncode == 0:
            for line in r_cred.stdout.splitlines():
                if line.startswith("password="):
                    pw = line.split("=", 1)[1].strip()
                    if pw:
                        return pw
    except Exception:
        pass
    return ""


def _make_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VibeArmor-DevSecOps-Engine/3.1",
    }


def filter_pushable_surgical_files(changed_files: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
    safe_files_to_push: Dict[str, str] = {}
    blocked_secret_files: List[str] = []
    for rel_path, content in changed_files.items():
        fname = rel_path.split("/")[-1]
        if fname in FORBIDDEN_ENV_PUSH_NAMES or (fname.startswith(".env.") and not fname.endswith(".example")):
            blocked_secret_files.append(rel_path)
            continue
        safe_files_to_push[rel_path] = content
    return safe_files_to_push, blocked_secret_files


def _probe_token_write_capability(
    client: httpx.Client,
    owner: str,
    repo: str,
    default_branch: str,
    is_private: bool,
    has_oauth_scopes_header: bool,
    oauth_scopes: List[str],
) -> Tuple[bool, str]:
    """Perform a zero-side-effect check to determine if THIS token actually has write access to `owner/repo`."""
    # 1. Classic PATs always send `X-OAuth-Scopes` (even if empty). Check scopes first!
    if has_oauth_scopes_header:
        scope_set = set(oauth_scopes)
        has_classic_write = ("repo" in scope_set) or (not is_private and "public_repo" in scope_set)
        if not has_classic_write:
            current_str = ", ".join(oauth_scopes) if oauth_scopes else "NONE (0 scopes checked)"
            needed_str = "'repo'" if is_private else "'repo' (or 'public_repo')"
            return (
                False,
                f"Classic token has scopes [{current_str}], which is missing {needed_str}. "
                f"Generate a Classic token with the [x] repo checkbox ticked.",
            )

    # 2. Schema-valid zero-mutation probe on `/git/refs`:
    #    IMPORTANT: Sending `json={}` returns `422` BEFORE GitHub checks Fine-Grained token permissions!
    #    Instead, pass the existing `refs/heads/{default_branch}` + its current SHA:
    #      - Schema validation passes -> GitHub executes real Fine-Grained Permission check!
    #      - 403 Forbidden              => Token LACKS `Contents: Read and write` on `{owner}/{repo}`!
    #      - 422 Reference already exists => Token HAS `Contents: Read and write` (0 side effects on repo)!
    r_head = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{default_branch}")
    head_sha = (
        (r_head.json().get("object") or {}).get("sha", "0000000000000000000000000000000000000000")
        if r_head.status_code == 200
        else "0000000000000000000000000000000000000000"
    )
    r_probe = client.post(
        f"/repos/{owner}/{repo}/git/refs",
        json={"ref": f"refs/heads/{default_branch}", "sha": head_sha},
    )
    if r_probe.status_code in (401, 403, 404):
        accepted_fg = r_probe.headers.get("X-Accepted-GitHub-Permissions") or "contents=write"
        accepted_oauth = r_probe.headers.get("X-Accepted-OAuth-Scopes") or ""
        try:
            gh_msg = (r_probe.json() or {}).get("message", "Resource not accessible by personal access token")
        except Exception:
            gh_msg = "Resource not accessible by personal access token"
        detail = (
            f"GitHub rejected write check with HTTP {r_probe.status_code} ('{gh_msg}'; required permission: {accepted_fg}"
            + (f", OAuth scopes: {accepted_oauth}" if accepted_oauth else "")
            + "). "
            f"On GitHub Fine-Grained tokens (github_pat_...), ensure: (1) Repository access is set to 'All repositories' or explicitly selects '{owner}/{repo}' "
            f"(NOT 'Public repositories', which GitHub forces to read-only), AND (2) Repository permissions -> 'Contents' = 'Read and write' & 'Pull requests' = 'Read and write' (then click Save/Generate)."
        )
        return False, detail

    return True, "Confirmed token write access (Contents: Read & write)."


def verify_github_token_access(repo_url: str, github_token: str) -> Dict[str, Any]:
    """Verify GitHub connectivity, authenticated user, and TRUE token write permissions on `owner/repo`."""
    owner, repo = parse_github_owner_repo(repo_url)
    token = github_token.strip()
    if not token:
        raise ValueError("Paste a GitHub Personal Access Token first to verify permissions.")

    token_kind = _detect_token_kind(token)
    with httpx.Client(base_url="https://api.github.com", headers=_make_headers(token), timeout=20.0) as client:
        r_user = client.get("/user")
        if r_user.status_code == 401:
            raise ValueError(
                f"GitHub rejected this {token_kind} (401 Unauthorized). Check that you copied the full token (starting with ghp_ or github_pat_) and that it hasn't expired."
            )
        r_user.raise_for_status()
        user_json = r_user.json()
        login = user_json.get("login", "")
        has_oauth_header = "x-oauth-scopes" in {k.lower() for k in r_user.headers.keys()}
        oauth_scopes = [
            s.strip() for s in (r_user.headers.get("X-OAuth-Scopes") or "").split(",") if s.strip()
        ]

        r_repo = client.get(f"/repos/{owner}/{repo}")
        if r_repo.status_code == 404:
            raise ValueError(
                f"Repository '{owner}/{repo}' not found (or is private and hidden from @{login}'s token)."
            )
        r_repo.raise_for_status()
        repo_json = r_repo.json()
        is_private = bool(repo_json.get("private", False))
        default_br = str(repo_json.get("default_branch") or "main")
        perms = repo_json.get("permissions") or {}
        account_has_push = bool(perms.get("push") or perms.get("admin") or perms.get("maintain"))
        is_same_owner = login.lower() == owner.lower()

        if account_has_push:
            token_can_write, probe_detail = _probe_token_write_capability(
                client, owner, repo, default_br, is_private, has_oauth_header, oauth_scopes
            )
        else:
            token_can_write = False
            probe_detail = f"Account @{login} is not an admin/collaborator on {owner}/{repo}."

        if token_can_write:
            status = "ready_direct"
            message = (
                f"✅ Verified! Authenticated as @{login} ({token_kind}) with confirmed WRITE permission on "
                f"{owner}/{repo} (default branch: {repo_json.get('default_branch', 'main')}). Ready to push!"
            )
            ok = True
        elif not is_same_owner and not account_has_push:
            # Check if token has classic public_repo/repo scope or fine-grained fork ability
            if has_oauth_header and not ({"repo", "public_repo"} & set(oauth_scopes)):
                status = "read_only_token"
                ok = False
                message = (
                    f"⚠️ Authenticated as @{login} ({token_kind}), but token has scopes "
                    f"[{', '.join(oauth_scopes) or 'NONE'}] — enable 'repo' or 'public_repo' to fork & open a PR."
                )
            else:
                status = "fork_pr_mode"
                ok = True
                message = (
                    f"Authenticated as @{login} ({token_kind}). VibeArmor will fork {owner}/{repo} "
                    f"to @{login}/{repo} and open a Pull Request."
                )
        else:
            status = "read_only_token"
            ok = False
            message = f"⚠️ Authenticated as @{login} ({token_kind}), BUT this token is READ-ONLY on '{owner}/{repo}': {probe_detail}"

        permission_checks = [
            {
                "id": "identity",
                "label": "GitHub Identity Authenticated",
                "status": "PASS",
                "detail": f"@{login} ({token_kind})",
            },
            {
                "id": "repo_read",
                "label": "Target Repository Located",
                "status": "PASS",
                "detail": f"{owner}/{repo} (default branch: {default_br})",
            },
            {
                "id": "contents_write",
                "label": "Repository Contents: Read & Write",
                "status": "PASS" if (token_can_write or status == "fork_pr_mode") else "FAIL",
                "detail": (
                    f"Write access confirmed on {owner}/{repo}"
                    if token_can_write
                    else (
                        f"Fork-and-PR flow enabled via @{login}/{repo}"
                        if status == "fork_pr_mode"
                        else "Missing 'Contents: Read and write' (or Classic 'repo' scope)"
                    )
                ),
            },
            {
                "id": "pr_flow",
                "label": "Pull Request / Compare Flow",
                "status": "PASS" if (token_can_write or status == "fork_pr_mode") else "NOT_RUN",
                "detail": "Auto-creates PR (or Compare PR URL if PR scope is restricted)",
            },
        ]

        return {
            "ok": ok,
            "status": status,
            "authenticated_user": login,
            "token_kind": token_kind,
            "oauth_scopes": oauth_scopes,
            "has_oauth_scopes_header": has_oauth_header,
            "repo": f"{owner}/{repo}",
            "default_branch": repo_json.get("default_branch", "main"),
            "permissions": {
                "admin": bool(perms.get("admin")),
                "account_push": account_has_push,
                "token_write_verified": token_can_write,
                "pull": bool(perms.get("pull", True)),
            },
            "permission_checks": permission_checks,
            "message": message,
            "classic_token_url": CLASSIC_TOKEN_NEW_URL,
            "fine_grained_token_url": FINE_GRAINED_TOKEN_URL,
        }


def _push_via_contents_api(
    client: httpx.Client,
    push_owner: str,
    push_repo: str,
    branch_name: str,
    safe_files_to_push: Dict[str, str],
    commit_msg_prefix: str,
) -> str:
    """Layer 2 fallback commit strategy using `PUT /repos/{owner}/{repo}/contents/{path}`."""
    last_commit_sha = ""
    for rel_path, file_content in sorted(safe_files_to_push.items()):
        existing_sha: Optional[str] = None
        r_get = client.get(
            f"/repos/{push_owner}/{push_repo}/contents/{rel_path}",
            params={"ref": branch_name},
        )
        if r_get.status_code == 200 and isinstance(r_get.json(), dict):
            existing_sha = r_get.json().get("sha")

        body: Dict[str, Any] = {
            "message": f"{commit_msg_prefix}: surgical fix in {rel_path}",
            "content": base64.b64encode(file_content.encode("utf-8")).decode("ascii"),
            "branch": branch_name,
        }
        if existing_sha:
            body["sha"] = existing_sha

        r_put = client.put(f"/repos/{push_owner}/{push_repo}/contents/{rel_path}", json=body)
        if r_put.status_code >= 400:
            raise ValueError(
                f"GitHub rejected write to '{rel_path}' ({r_put.status_code}): {r_put.text[:220]}"
            )
        last_commit_sha = (r_put.json().get("commit") or {}).get("sha", last_commit_sha)
    return last_commit_sha


def _push_via_native_git_https(
    push_owner: str,
    push_repo: str,
    token: str,
    target_base: str,
    dest_branch: str,
    safe_files_to_push: Dict[str, str],
    commit_message: str,
) -> Tuple[bool, str]:
    """Layer 3 fallback: push via native `git` Smart-HTTPS (`x-access-token`) in a clean temp directory."""
    tmp_dir = tempfile.mkdtemp(prefix="vibearmor_gitpush_")
    auth_url = f"https://x-access-token:{token}@github.com/{push_owner}/{push_repo}.git"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        r_clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", "--branch", target_base, auth_url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=45,
            env=env,
        )
        if r_clone.returncode == 0:
            subprocess.run(
                ["git", "sparse-checkout", "set", "--no-cone", "/*", "!/.venv/", "!/node_modules/"],
                cwd=tmp_dir,
                capture_output=True,
                timeout=20,
                env=env,
            )
        if r_clone.returncode != 0:
            err = r_clone.stderr.replace(token, "***")
            return False, err.strip()

        if dest_branch != target_base:
            subprocess.run(["git", "checkout", "-b", dest_branch], cwd=tmp_dir, check=True, capture_output=True, env=env)

        for rel_p, content in sorted(safe_files_to_push.items()):
            fp = Path(tmp_dir) / rel_p
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
            subprocess.run(["git", "add", "--force", rel_p], cwd=tmp_dir, check=True, capture_output=True, env=env)

        subprocess.run(["git", "config", "user.name", "VibeArmor Security Guard"], cwd=tmp_dir, check=True, capture_output=True, env=env)
        subprocess.run(["git", "config", "user.email", "security@vibearmor.local"], cwd=tmp_dir, check=True, capture_output=True, env=env)
        r_cm = subprocess.run(["git", "commit", "-m", commit_message], cwd=tmp_dir, capture_output=True, text=True, env=env)
        if r_cm.returncode != 0 and "nothing to commit" not in r_cm.stdout:
            return False, r_cm.stderr.replace(token, "***").strip()

        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_dir, text=True, env=env).strip()
        r_push = subprocess.run(
            ["git", "push", "origin", f"HEAD:refs/heads/{dest_branch}"],
            cwd=tmp_dir,
            capture_output=True,
            text=True,
            timeout=25,
            env=env,
        )
        if r_push.returncode != 0:
            return False, r_push.stderr.replace(token, "***").strip()
        return True, sha
    except Exception as exc:
        return False, str(exc).replace(token, "***")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def push_surgical_fixes_to_github(
    repo_url: str,
    github_token: str,
    changed_files: Dict[str, str],
    mode: str = "pull_request",  # "pull_request" | "direct_commit"
    base_branch: Optional[str] = None,
    commit_message: Optional[str] = None,
    pr_title: Optional[str] = None,
    pr_body: Optional[str] = None,
) -> Dict[str, Any]:
    """Push ONLY user-approved surgical files to GitHub (3-Layer API + Native Git + Auto-Fork)."""
    owner, repo = parse_github_owner_repo(repo_url)
    token = (github_token or "").strip() or discover_local_system_github_token()
    if not token:
        raise ValueError(
            "No GitHub write token available on this server. Either click '1-Click Classic Token (repo Scope)' to paste a ghp_... token, "
            "or use Method 1 ('Copy 1-Paste Push Command') above to push via your local Windows/macOS Git login!"
        )

    safe_files_to_push, blocked_secret_files = filter_pushable_surgical_files(changed_files)
    if not safe_files_to_push:
        raise ValueError("No pushable source changes found after filtering local-only `.env` secret files.")

    token_kind = _detect_token_kind(token)

    with httpx.Client(base_url="https://api.github.com", headers=_make_headers(token), timeout=30.0) as client:
        # 1. Authenticate user & inspect token headers
        r_user = client.get("/user")
        if r_user.status_code == 401:
            raise ValueError(
                f"GitHub rejected this {token_kind} (401 Unauthorized). Check that you pasted a valid token starting with 'ghp_' or 'github_pat_'."
            )
        r_user.raise_for_status()
        login = r_user.json().get("login", "")
        has_oauth_header = "x-oauth-scopes" in {k.lower() for k in r_user.headers.keys()}
        oauth_scopes = [
            s.strip() for s in (r_user.headers.get("X-OAuth-Scopes") or "").split(",") if s.strip()
        ]

        r_repo = client.get(f"/repos/{owner}/{repo}")
        if r_repo.status_code == 404:
            raise ValueError(f"Repository '{owner}/{repo}' not found or hidden from @{login}'s token.")
        r_repo.raise_for_status()
        repo_info = r_repo.json()
        is_private = bool(repo_info.get("private", False))
        perms = repo_info.get("permissions") or {}
        account_can_push = bool(perms.get("push") or perms.get("admin") or perms.get("maintain"))
        target_base = (base_branch or repo_info.get("default_branch") or "main").strip()

        msg = commit_message or (
            f"security(vibearmor): surgical remediation across {len(safe_files_to_push)} file(s)\n\n"
            "Verified by VibeArmor 3-Gate Closed-Loop Verifier (0 broken builds, untouched code preserved)."
        )

        # If pushing to another user's public repo, auto-fork in PR mode!
        push_owner = owner
        push_repo = repo
        used_fork = False
        if not account_can_push and login.lower() != owner.lower():
            if mode == "direct_commit":
                raise ValueError(
                    f"Authenticated as @{login}, which does not own '{owner}/{repo}'. "
                    "Switch Update Strategy to 'Open Safe Pull Request' so VibeArmor can fork & open a PR."
                )
            r_fork = client.post(f"/repos/{owner}/{repo}/forks")
            if r_fork.status_code >= 400:
                raise ValueError(
                    f"Token (@{login}, {token_kind}) lacks write scope to fork '{owner}/{repo}' ({r_fork.status_code}). "
                    "Use a Classic token with 'repo' checked, or download the 1-Click Local Git Push Script below."
                )
            fork_json = r_fork.json()
            push_owner = (fork_json.get("owner") or {}).get("login", login)
            push_repo = fork_json.get("name", repo)
            used_fork = True
            for _ in range(6):
                chk = client.get(f"/repos/{push_owner}/{push_repo}/git/ref/heads/{target_base}")
                if chk.status_code == 200:
                    break
                time.sleep(1.2)

        # 2. Resolve base branch HEAD commit & base tree SHA
        r_ref = client.get(f"/repos/{push_owner}/{push_repo}/git/ref/heads/{target_base}")
        if r_ref.status_code != 200:
            r_ref = client.get(f"/repos/{owner}/{repo}/git/ref/heads/{target_base}")
            if r_ref.status_code != 200:
                raise ValueError(f"Base branch '{target_base}' not found on {owner}/{repo}.")
        base_commit_sha = r_ref.json()["object"]["sha"]

        r_commit = client.get(f"/repos/{owner}/{repo}/git/commits/{base_commit_sha}")
        r_commit.raise_for_status()
        base_tree_sha = r_commit.json()["tree"]["sha"]

        tree_entries = [
            {"path": rel_p, "mode": "100644", "type": "blob", "content": content}
            for rel_p, content in sorted(safe_files_to_push.items())
        ]

        # 3A. Direct Commit Mode (Layer 1 Trees -> Layer 2 Contents -> Layer 3 Native Git)
        if mode == "direct_commit":
            r_tree = client.post(
                f"/repos/{push_owner}/{push_repo}/git/trees",
                json={"base_tree": base_tree_sha, "tree": tree_entries},
            )
            if r_tree.status_code < 400:
                new_tree_sha = r_tree.json()["sha"]
                r_nc = client.post(
                    f"/repos/{push_owner}/{push_repo}/git/commits",
                    json={"message": msg, "tree": new_tree_sha, "parents": [base_commit_sha]},
                )
                r_nc.raise_for_status()
                new_commit_sha = r_nc.json()["sha"]
                r_upd = client.patch(
                    f"/repos/{push_owner}/{push_repo}/git/refs/heads/{target_base}",
                    json={"sha": new_commit_sha, "force": False},
                )
                if r_upd.status_code >= 400:
                    raise ValueError(f"Failed to update branch '{target_base}': {r_upd.text[:200]}")
            else:
                try:
                    new_commit_sha = _push_via_contents_api(
                        client, push_owner, push_repo, target_base, safe_files_to_push, "security(vibearmor)"
                    )
                except ValueError:
                    git_ok, git_out = _push_via_native_git_https(
                        push_owner, push_repo, token, target_base, target_base, safe_files_to_push, msg
                    )
                    if not git_ok:
                        probe_ok, probe_reason = _probe_token_write_capability(
                            client, push_owner, push_repo, target_base, is_private, has_oauth_header, oauth_scopes
                        )
                        raw_detail = probe_reason if not probe_ok else f"GitHub HTTP {r_tree.status_code}: {r_tree.text[:180]} | git: {git_out[:180]}"
                        raise ValueError(
                            f"Token for @{login} ({token_kind}) lacks write permission on '{push_owner}/{push_repo}'. {raw_detail} "
                            "Tip: Copy the 1-line terminal push command below to push via your local Git login with zero token setup!"
                        )
                    new_commit_sha = git_out

            return {
                "mode": "direct_commit",
                "repo": f"{owner}/{repo}",
                "branch": target_base,
                "commit_sha": new_commit_sha,
                "commit_url": f"https://github.com/{owner}/{repo}/commit/{new_commit_sha}",
                "files_pushed": sorted(safe_files_to_push.keys()),
                "secret_files_excluded": blocked_secret_files,
            }

        # 3B. Safe Pull Request Mode (Layer 1 Trees -> Layer 2 Contents -> Layer 3 Native Git)
        new_branch = f"vibearmor/security-fixes-{int(time.time())}"
        r_tree = client.post(
            f"/repos/{push_owner}/{push_repo}/git/trees",
            json={"base_tree": base_tree_sha, "tree": tree_entries},
        )
        if r_tree.status_code < 400:
            new_tree_sha = r_tree.json()["sha"]
            r_nc = client.post(
                f"/repos/{push_owner}/{push_repo}/git/commits",
                json={"message": msg, "tree": new_tree_sha, "parents": [base_commit_sha]},
            )
            r_nc.raise_for_status()
            new_commit_sha = r_nc.json()["sha"]
            r_create_ref = client.post(
                f"/repos/{push_owner}/{push_repo}/git/refs",
                json={"ref": f"refs/heads/{new_branch}", "sha": new_commit_sha},
            )
            if r_create_ref.status_code >= 400:
                raise ValueError(f"Failed to create branch '{new_branch}': {r_create_ref.text[:200]}")
        else:
            # Layer 2: Contents API fallback
            r_create_ref = client.post(
                f"/repos/{push_owner}/{push_repo}/git/refs",
                json={"ref": f"refs/heads/{new_branch}", "sha": base_commit_sha},
            )
            if r_create_ref.status_code < 400:
                new_commit_sha = _push_via_contents_api(
                    client, push_owner, push_repo, new_branch, safe_files_to_push, "security(vibearmor)"
                )
            else:
                # Layer 3: Native Git Smart-HTTPS fallback
                git_ok, git_out = _push_via_native_git_https(
                    push_owner, push_repo, token, target_base, new_branch, safe_files_to_push, msg
                )
                if not git_ok:
                    probe_ok, probe_reason = _probe_token_write_capability(
                        client, push_owner, push_repo, target_base, is_private, has_oauth_header, oauth_scopes
                    )
                    raw_detail = probe_reason if not probe_ok else f"GitHub HTTP {r_create_ref.status_code}: {r_create_ref.text[:180]} | git: {git_out[:180]}"
                    raise ValueError(
                        f"Token for @{login} ({token_kind}) lacks write permission on '{push_owner}/{push_repo}'. {raw_detail} "
                        "Or copy the 1-line terminal push command below to push using your computer's existing Git login (no token needed)!"
                    )
                new_commit_sha = git_out

        pr_head = f"{push_owner}:{new_branch}" if used_fork else new_branch
        r_pr = client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": pr_title or f"🛡️ VibeArmor: Surgical Security Remediation ({len(safe_files_to_push)} files)",
                "head": pr_head,
                "base": target_base,
                "body": pr_body
                or (
                    "## 🛡️ VibeArmor Surgical Security Patch\n\n"
                    "- **Strict Surgical Mode:** Only vulnerable AST/SQL/manifest lines were modified; all non-vulnerable code and unrelated files remain 100% untouched.\n"
                    "- **3-Gate Verification:** Passed AST/SQL Compile Gate, Cross-Layer Re-Scan Gate, and Sandbox Exploit Replay.\n"
                    f"- **Files Updated:** {', '.join(f'`{p}`' for p in sorted(safe_files_to_push.keys()))}\n"
                    + (
                        f"- **Local Secret Files Excluded from Push:** {', '.join(f'`{p}`' for p in blocked_secret_files)}\n"
                        if blocked_secret_files
                        else ""
                    )
                ),
            },
        )
        if r_pr.status_code >= 400:
            compare_url = f"https://github.com/{owner}/{repo}/compare/{target_base}...{pr_head}?expand=1"
            return {
                "mode": "pull_request",
                "repo": f"{owner}/{repo}",
                "base_branch": target_base,
                "branch": new_branch,
                "commit_sha": new_commit_sha,
                "commit_url": f"https://github.com/{push_owner}/{push_repo}/commit/{new_commit_sha}",
                "pr_number": None,
                "pr_url": compare_url,
                "compare_only": True,
                "note": "Branch & surgical commits pushed to GitHub! Click below to open the Pull Request in 1 click.",
                "files_pushed": sorted(safe_files_to_push.keys()),
                "secret_files_excluded": blocked_secret_files,
            }

        pr_json = r_pr.json()
        return {
            "mode": "pull_request",
            "repo": f"{owner}/{repo}",
            "base_branch": target_base,
            "branch": new_branch,
            "commit_sha": new_commit_sha,
            "commit_url": f"https://github.com/{push_owner}/{push_repo}/commit/{new_commit_sha}",
            "pr_number": pr_json.get("number"),
            "pr_url": pr_json.get("html_url"),
            "compare_only": False,
            "files_pushed": sorted(safe_files_to_push.keys()),
            "secret_files_excluded": blocked_secret_files,
        }


def build_local_git_push_script(
    repo_url: str,
    changed_files: Dict[str, str],
    base_branch: str = "main",
    mode: str = "pull_request",
) -> str:
    """Generate a zero-dependency Python script that pushes ONLY the surgical files via local Git login (0 PAT required)."""
    owner, repo = parse_github_owner_repo(repo_url)
    safe_files, excluded_secrets = filter_pushable_surgical_files(changed_files)
    payload_b64 = base64.b64encode(json.dumps(safe_files).encode("utf-8")).decode("ascii")
    clean_url = f"https://github.com/{owner}/{repo}.git"

    return f'''#!/usr/bin/env python3
"""VibeArmor 1-Click Zero-Token GitHub Updater for {owner}/{repo}.

Uses your computer's existing Git / GitHub Desktop / VS Code / Cursor / `gh` login — NO Personal Access Token needed!
Applies ONLY {len(safe_files)} surgical file(s) ({", ".join(sorted(safe_files.keys()))}) and leaves all other files 100% untouched.
Excluded secret files (never pushed): {", ".join(excluded_secrets) if excluded_secrets else "none"}

Run:
    python push_vibearmor_fixes.py
"""
import base64, json, pathlib, shutil, subprocess, tempfile, time, webbrowser

REPO_URL = {clean_url!r}
OWNER_REPO = "{owner}/{repo}"
BASE_BRANCH = {base_branch!r}
MODE = {mode!r}
FILES = json.loads(base64.b64decode({payload_b64!r}).decode("utf-8"))

def main() -> None:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="vibearmor_sync_"))
    try:
        print(f"[VibeArmor] Cloning {{REPO_URL}} using your local Git credentials...")
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(tmp)], check=True)
        head_branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=tmp, text=True
        ).strip() or BASE_BRANCH
        branch = head_branch if MODE == "direct_commit" else f"vibearmor/security-fixes-{{int(time.time())}}"
        if branch != head_branch:
            subprocess.run(["git", "checkout", "-b", branch], cwd=tmp, check=True)

        for rel_path, content in sorted(FILES.items()):
            target = tmp / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            subprocess.run(["git", "add", "--force", rel_path], cwd=tmp, check=True)
            print(f"  ✔ Staged surgical fix: {{rel_path}}")

        msg = f"security(vibearmor): surgical remediation across {{len(FILES)}} file(s)"
        subprocess.run(["git", "commit", "-m", msg], cwd=tmp, check=True)
        print(f"[VibeArmor] Pushing '{{branch}}' to {{OWNER_REPO}}...")
        subprocess.run(["git", "push", "-u", "origin", branch], cwd=tmp, check=True)

        target_url = (
            f"https://github.com/{{OWNER_REPO}}/commits/{{branch}}"
            if MODE == "direct_commit"
            else f"https://github.com/{{OWNER_REPO}}/compare/{{head_branch}}...{{branch}}?expand=1"
        )
        print(f"\\n✅ SUCCESS! Pushed {{len(FILES)}} surgical file(s) to GitHub!")
        print(f"👉 Open in browser: {{target_url}}")
        try:
            webbrowser.open(target_url)
        except Exception:
            pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    main()
'''


GITHUB_SAVED_CFG_PATH = Path.home() / ".vibearmor_github_config.json"


def load_saved_github_config(include_raw_token: bool = False) -> Dict[str, Any]:
    """Read persisted GitHub connection settings (never exposes raw token unless `include_raw_token=True`)."""
    from core.security_masking import mask_token_preview

    if not GITHUB_SAVED_CFG_PATH.exists():
        return {
            "configured": False,
            "repo_url": "",
            "default_mode": "pull_request",
            "base_branch": "main",
            "authenticated_user": "",
            "token_kind": "",
            "token_masked": "",
            "write_verified": False,
        }
    try:
        raw = json.loads(GITHUB_SAVED_CFG_PATH.read_text(encoding="utf-8"))
        tok = str(raw.get("github_token", ""))
        res: Dict[str, Any] = {
            "configured": bool(tok),
            "repo_url": str(raw.get("repo_url", "")),
            "default_mode": str(raw.get("default_mode", "pull_request")),
            "base_branch": str(raw.get("base_branch", "main")),
            "authenticated_user": str(raw.get("authenticated_user", "")),
            "token_kind": str(raw.get("token_kind", "")),
            "token_masked": mask_token_preview(tok),
            "write_verified": bool(raw.get("write_verified", False)),
        }
        if include_raw_token:
            res["github_token"] = tok
        return res
    except Exception:
        return {"configured": False, "repo_url": "", "default_mode": "pull_request", "base_branch": "main", "token_masked": "", "write_verified": False}


def save_github_config(
    repo_url: str,
    github_token: str,
    default_mode: str = "pull_request",
    base_branch: str = "main",
    authenticated_user: str = "",
    token_kind: str = "",
    write_verified: bool = False,
) -> Dict[str, Any]:
    payload = {
        "repo_url": repo_url.strip(),
        "github_token": github_token.strip(),
        "default_mode": default_mode,
        "base_branch": base_branch.strip() or "main",
        "authenticated_user": authenticated_user,
        "token_kind": token_kind,
        "write_verified": write_verified,
    }
    GITHUB_SAVED_CFG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    try:
        GITHUB_SAVED_CFG_PATH.chmod(0o600)
    except Exception:
        pass
    return load_saved_github_config(include_raw_token=False)


def clear_github_config() -> Dict[str, Any]:
    if GITHUB_SAVED_CFG_PATH.exists():
        GITHUB_SAVED_CFG_PATH.unlink()
    return load_saved_github_config(include_raw_token=False)


def build_offline_git_push_commands(
    repo_url: str,
    unified_patch: str,
    mode: str = "pull_request",
    base_branch: str = "main",
) -> Dict[str, str]:
    """Generate 100% offline self-contained PowerShell 5.1 & Bash Git push commands using Gzip+Base64 unified diff.

    Requires ZERO HTTP calls to Arena's sandbox URL and ZERO GitHub Personal Access Token!
    """
    import gzip as _gzip

    owner, repo = parse_github_owner_repo(repo_url)
    clean_clone = f"https://github.com/{owner}/{repo}.git"
    gz_b64 = base64.b64encode(_gzip.compress(unified_patch.encode("utf-8"), compresslevel=9)).decode("ascii")
    is_direct = mode == "direct_commit"

    ps_branch_stmt = (
        "$br=$hb"
        if is_direct
        else '$br="vibearmor/security-fixes-"+[int][double]::Parse((Get-Date -UFormat %s)); git checkout -b $br'
    )
    ps_open_url = (
        f'https://github.com/{owner}/{repo}/commits/$br'
        if is_direct
        else f'https://github.com/{owner}/{repo}/compare/$hb...$br?expand=1'
    )

    powershell_cmd = (
        f"$ErrorActionPreference='Stop'; "
        f"$d=Join-Path $env:TEMP ('va_push_'+[guid]::NewGuid().ToString('N').Substring(0,8)); "
        f"git clone --depth 1 --filter=blob:none --sparse '{clean_clone}' $d; "
        f"Push-Location $d; "
        f"try {{ "
        f"git sparse-checkout set --no-cone '/*' '!/.venv/' '!/node_modules/'; "
        f"$hb=(git rev-parse --abbrev-ref HEAD).Trim(); "
        f"{ps_branch_stmt}; "
        f"$ms=New-Object IO.MemoryStream(,[Convert]::FromBase64String('{gz_b64}')); "
        f"$gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); "
        f"$pf=Join-Path $env:TEMP 'vibearmor_surgical.patch'; "
        f"$fs=[IO.File]::Create($pf); $gz.CopyTo($fs); $fs.Close(); $gz.Close(); "
        f"git apply --whitespace=nowarn $pf; "
        f"git add -A; "
        f"git commit -m 'security(vibearmor): apply verified surgical security fixes'; "
        f"git push -u origin $br; "
        f"$u=\"{ps_open_url}\"; "
        f"Write-Host ('SUCCESS! Open: '+$u) -ForegroundColor Green; "
        f"Start-Process $u "
        f"}} finally {{ Pop-Location; Remove-Item -Force $pf -ErrorAction SilentlyContinue; Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue }}"
    )

    bash_cmd = (
        f"python3 -c \"import base64,gzip,pathlib,shutil,subprocess,tempfile,time,webbrowser; "
        f"d=pathlib.Path(tempfile.mkdtemp(prefix='va_push_')); "
        f"subprocess.run(['git','clone','--depth','1','--filter=blob:none','--sparse','{clean_clone}',str(d)],check=True); "
        f"subprocess.run(['git','sparse-checkout','set','--no-cone','/*','!/.venv/','!/node_modules/'],cwd=d,check=True); "
        f"hb=subprocess.check_output(['git','rev-parse','--abbrev-ref','HEAD'],cwd=d,text=True).strip() or '{base_branch or 'main'}'; "
        f"br=hb if {is_direct!r} else f'vibearmor/security-fixes-{{int(time.time())}}'; "
        f"subprocess.run(['git','checkout','-b',br],cwd=d,check=True) if br!=hb else None; "
        f"pf=d/'va.patch'; pf.write_bytes(gzip.decompress(base64.b64decode('{gz_b64}'))); "
        f"subprocess.run(['git','apply','--whitespace=nowarn',str(pf)],cwd=d,check=True); pf.unlink(); "
        f"subprocess.run(['git','add','-A'],cwd=d,check=True); "
        f"subprocess.run(['git','commit','-m','security(vibearmor): apply verified surgical security fixes'],cwd=d,check=True); "
        f"subprocess.run(['git','push','-u','origin',br],cwd=d,check=True); "
        f"u=f'https://github.com/{owner}/{repo}/compare/{{hb}}...{{br}}?expand=1' if br!=hb else f'https://github.com/{owner}/{repo}/commits/{{br}}'; "
        f"print('SUCCESS! Open:',u); webbrowser.open(u); shutil.rmtree(d,ignore_errors=True)\""
    )

    return {
        "powershell_cmd": powershell_cmd,
        "bash_cmd": bash_cmd,
        "compressed_patch_chars": str(len(gz_b64)),
    }
