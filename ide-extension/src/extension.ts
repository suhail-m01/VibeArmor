/**
 * VibeArmor v3.6 Multi-Editor Extension (VS Code · Cursor · Windsurf · VSCodium · Antigravity · Trae)
 * Features:
 *  1. Dual-Engine Operation: Connects to VibeArmor Studio Server (Neuro-Symbolic + Security RAG + LangGraph)
 *     AND automatically falls back to a Built-In Offline AST/Rule Security Engine when running standalone!
 *  2. Exact-Range Quick Fix CodeActionProvider (💡 Lightbulb) — patches ONLY the vulnerable line span, never 0..EOF.
 *  3. Auto Git Discovery, Safe `git init -b main`, `.venv`/`node_modules`/`.env` `.gitignore` Shield,
 *     1-Click GitHub Remote (`origin`) Setup, Non-Fast-Forward PR/Rebase/Force Recovery & Integrated Terminal Fallback.
 */
import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as http from "http";
import * as https from "https";
import { execFile, execFileSync } from "child_process";

interface DiagnosticItem {
  id: string;
  rule_id: string;
  cwe?: string;
  severity: string;
  title: string;
  description: string;
  file_path: string;
  line_start: number;
  line_end: number;
}

interface ProposalFileDiff {
  file_path: string;
  created_new: boolean;
  before_content: string;
  after_content: string;
  precision?: {
    preservation_pct: number;
    changed_span_label: string;
    vulnerable_excerpt: string;
    corrected_excerpt: string;
  };
}

interface ProposalItem {
  finding_id: string;
  rule_id: string;
  cwe?: string;
  severity: string;
  title: string;
  file_path: string;
  line_start: number;
  adoptable: boolean;
  precision?: {
    preservation_pct: number;
    changed_span_label: string;
    vulnerable_excerpt: string;
    corrected_excerpt: string;
  };
  file_diffs: ProposalFileDiff[];
}

interface ReadinessResponse {
  session_id: string;
  engine_mode?: "studio_server" | "builtin_offline";
  project_id?: string;
  ready_to_push: boolean;
  ready_to_deploy: boolean;
  security_score: number;
  blocking_count: number;
  node_count?: number;
  edge_count?: number;
  checks: Record<string, { passed: boolean; count: number; label: string }>;
  findings: DiagnosticItem[];
  proposals: ProposalItem[];
}

interface GitRepoStatus {
  isGitRepo: boolean;
  repoDir: string;
  branch: string;
  remoteUrl: string;
  childRepos: string[];
}

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "__pycache__",
  ".venv",
  "venv",
  ".vibearmor",
  ".pytest_cache",
]);

const SCANNABLE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".sql", ".json"]);
const SCANNABLE_NAMES = new Set(["package.json", "requirements.txt", ".gitignore", "cloud_drift_catalog.json"]);

const KNOWN_SLOPSQUAT_PKGS: Record<string, string> = {
  "react-router-dom-v7-ai": "react-router-dom",
  "fastapi-jwt-helper-ai": "PyJWT",
  "supabase-auth-magic": "@supabase/supabase-js",
  "openai-chat-fast": "openai",
  "langchain-rag-turbo": "langchain",
};

const SAFE_GITIGNORE_ENTRIES = [
  ".env",
  ".env.local",
  ".env.production",
  ".env.*.local",
  ".venv/",
  "venv/",
  "node_modules/",
  "__pycache__/",
  "*.pyc",
  ".pytest_cache/",
  ".vibearmor/",
];

export function maskSecrets(input: string): string {
  if (!input) return "";
  return input
    .replace(/\b(sk_(?:live|test)_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}\b/g, "$1************")
    .replace(/\b(sk-[A-Za-z0-9]{4})[A-Za-z0-9-_]{12,}\b/g, "$1************")
    .replace(/\b(ghp_[A-Za-z0-9]{4})[A-Za-z0-9]{16,}\b/g, "$1************")
    .replace(/\b(github_pat_[A-Za-z0-9_]{6})[A-Za-z0-9_]{16,}\b/g, "$1************")
    .replace(/\b(AIza[0-9A-Za-z-_]{4})[0-9A-Za-z-_]{16,}\b/g, "$1************")
    .replace(/\b(rzp_(?:live|test)_[A-Za-z0-9]{4})[A-Za-z0-9]{8,}\b/g, "$1************");
}

/** Normalize any GitHub URL or shorthand (`owner/repo`, browser `/tree/main` URL, SSH, HTTPS) into a valid Git remote URL. */
export function normalizeGitHubRemoteUrl(rawInput: string): string {
  let s = (rawInput || "").trim().replace(/^["']+|["']+$/g, "");
  if (!s) return "";
  if (s.startsWith("git@github.com:")) {
    const slug = s.slice("git@github.com:".length).replace(/\/+$/, "").replace(/\.git$/i, "");
    return `git@github.com:${slug}.git`;
  }
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(s)) {
    const cleanSlug = s.replace(/\.git$/i, "");
    return `https://github.com/${cleanSlug}.git`;
  }
  try {
    const u = new URL(s);
    if (u.hostname.toLowerCase().includes("github.com")) {
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length >= 2) {
        const owner = parts[0];
        const repo = parts[1].replace(/\.git$/i, "");
        return `${u.protocol}//${u.host}/${owner}/${repo}.git`;
      }
    }
  } catch {
    // keep raw string if custom git host
  }
  return s;
}

export function extractGitHubWebRepoUrl(remoteUrl: string): string | null {
  if (!remoteUrl) return null;
  const sshMatch = remoteUrl.match(/^git@github\.com:([^/]+)\/([^/]+?)(?:\.git)?$/i);
  if (sshMatch) {
    return `https://github.com/${sshMatch[1]}/${sshMatch[2]}`;
  }
  try {
    const u = new URL(remoteUrl);
    if (u.hostname.toLowerCase().includes("github.com")) {
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length >= 2) {
        return `https://github.com/${parts[0]}/${parts[1].replace(/\.git$/i, "")}`;
      }
    }
  } catch {
    return null;
  }
  return null;
}

/** True check via `git rev-parse --is-inside-work-tree` (catches uninitialized folders AND broken `.git/hooks`-only folders!). */
export function isValidGitWorktree(dir: string): boolean {
  try {
    const out = execFileSync("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd: dir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out === "true";
  } catch {
    return false;
  }
}

function getGitTopLevel(dir: string): string | null {
  try {
    const top = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: dir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return top ? path.normalize(top) : null;
  } catch {
    return null;
  }
}

function findChildGitRepos(rootDir: string): string[] {
  const found: string[] = [];
  try {
    const entries = fs.readdirSync(rootDir, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory() || IGNORED_DIRS.has(ent.name) || ent.name.startsWith(".")) continue;
      const sub = path.join(rootDir, ent.name);
      if (fs.existsSync(path.join(sub, ".git")) && isValidGitWorktree(sub)) {
        found.push(sub);
      }
    }
  } catch {
    // ignore
  }
  return found;
}

function runGitAsync(cwd: string, args: string[], timeoutMs = 90000): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      args,
      {
        cwd,
        timeout: timeoutMs,
        maxBuffer: 12 * 1024 * 1024,
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        if (err) {
          const detail = (stderr || stdout || err.message || "").trim();
          reject(new Error(detail || err.message));
          return;
        }
        resolve({ stdout: String(stdout || ""), stderr: String(stderr || "") });
      }
    );
  });
}

/** Ensure `.gitignore` protects `.env`, `.venv/`, `node_modules/`, etc. before `git add -A` ever runs! */
export function ensureSafeGitignore(repoDir: string): void {
  const giPath = path.join(repoDir, ".gitignore");
  let existing = "";
  try {
    if (fs.existsSync(giPath)) {
      existing = fs.readFileSync(giPath, "utf-8");
    }
  } catch {
    existing = "";
  }
  const existingLines = new Set(
    existing
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
  );
  const missing = SAFE_GITIGNORE_ENTRIES.filter((entry) => {
    const bare = entry.replace(/\/$/, "");
    return !existingLines.has(entry) && !existingLines.has(bare) && !existingLines.has(`/${entry}`);
  });
  if (missing.length > 0) {
    const prefix = existing && !existing.endsWith("\n") ? "\n" : "";
    const block = `${prefix}# VibeArmor Safe Git Push Protection (secrets & virtualenvs)\n${missing.join("\n")}\n`;
    fs.writeFileSync(giPath, existing + block, "utf-8");
  }
}

/** Compute exact minimal changed line range between beforeContent and afterContent (never 0..10000!). */
export function computeMinimalLinePatch(beforeContent: string, afterContent: string): {
  startLine: number;
  endLine: number;
  endChar: number;
  replacementText: string;
} {
  const bLines = beforeContent.split(/\r?\n/);
  const aLines = afterContent.split(/\r?\n/);

  let prefix = 0;
  while (prefix < bLines.length && prefix < aLines.length && bLines[prefix] === aLines[prefix]) {
    prefix++;
  }
  if (prefix === bLines.length && prefix === aLines.length) {
    return { startLine: 0, endLine: 0, endChar: 0, replacementText: bLines[0] || "" };
  }

  let suffix = 0;
  while (
    suffix < bLines.length - prefix &&
    suffix < aLines.length - prefix &&
    bLines[bLines.length - 1 - suffix] === aLines[aLines.length - 1 - suffix]
  ) {
    suffix++;
  }

  const bEndIdx = Math.max(prefix, bLines.length - 1 - suffix);
  const aEndSlice = aLines.slice(prefix, aLines.length - suffix);

  if (bLines.length - prefix - suffix === 0) {
    const existingLine = bLines[Math.min(prefix, bLines.length - 1)] ?? "";
    const joinedInsert = aEndSlice.join("\n") + (prefix < bLines.length ? "\n" + existingLine : "");
    return {
      startLine: Math.min(prefix, Math.max(0, bLines.length - 1)),
      endLine: Math.min(prefix, Math.max(0, bLines.length - 1)),
      endChar: existingLine.length,
      replacementText: joinedInsert,
    };
  }

  return {
    startLine: prefix,
    endLine: bEndIdx,
    endChar: (bLines[bEndIdx] ?? "").length,
    replacementText: aEndSlice.join("\n"),
  };
}

function isSyntheticBenchmarkPath(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase();
  return (
    norm.startsWith("eval/datasets/") ||
    norm.includes("/eval/datasets/") ||
    norm.endsWith("eval/generate_suites.py") ||
    norm.startsWith("vibebazaar-demo/") ||
    norm.includes("/vibebazaar-demo/") ||
    norm.endsWith("tests/test_vibearmor_e2e.py") ||
    norm.endsWith("core/interfaces/live_target.py") ||
    norm.endsWith("core/verifier/gate3_poc_probe.py") ||
    norm.endsWith("core/rag/security_rag.py") ||
    norm.endsWith("ide-extension/vibearmor_bridge.py")
  );
}

/** Built-in standalone security engine so the VSIX works 100% offline on any laptop even before starting Studio! */
function runBuiltInLocalSecurityAudit(files: Array<{ path: string; content: string }>): ReadinessResponse {
  const findings: DiagnosticItem[] = [];
  const proposals: ProposalItem[] = [];
  let idx = 1;

  const secretRe =
    /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']((?:sk_(?:live|test)_|sk-|ghp_|github_pat_|AIza|rzp_(?:live|test)_)[A-Za-z0-9_-]{10,}|[A-Za-z0-9_\-]{20,})["']/i;

  for (const file of files) {
    const rel = file.path;
    if (isSyntheticBenchmarkPath(rel)) continue;

    const ext = path.extname(rel).toLowerCase();
    const lines = file.content.split(/\r?\n/);

    // 1. Public env secret prefix check (.env*)
    if (path.basename(rel).startsWith(".env")) {
      lines.forEach((ln, i) => {
        const m = ln.match(/^\s*((?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|KEY)[A-Z0-9_]*)\s*=/);
        if (m) {
          const fid = `local-${idx++}`;
          const safeVar = m[1].replace(/^(?:NEXT_PUBLIC_|VITE_|REACT_APP_)/, "");
          const fixedLine = ln.replace(m[1], safeVar);
          const nextLines = [...lines];
          nextLines[i] = fixedLine;
          findings.push({
            id: fid,
            rule_id: "VA-ENV-002",
            cwe: "CWE-200",
            severity: "CRITICAL",
            title: `Private credential exposed with browser prefix '${m[1]}'`,
            description: "Variables prefixed with NEXT_PUBLIC_/VITE_/REACT_APP_ are bundled into public browser JS.",
            file_path: rel,
            line_start: i + 1,
            line_end: i + 1,
          });
          proposals.push({
            finding_id: fid,
            rule_id: "VA-ENV-002",
            cwe: "CWE-200",
            severity: "CRITICAL",
            title: `Strip public browser prefix -> '${safeVar}'`,
            file_path: rel,
            line_start: i + 1,
            adoptable: true,
            precision: {
              preservation_pct: 99,
              changed_span_label: `Line ${i + 1}`,
              vulnerable_excerpt: maskSecrets(ln.trim()),
              corrected_excerpt: maskSecrets(fixedLine.trim()),
            },
            file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: nextLines.join("\n") }],
          });
        }
      });
      continue;
    }

    // 2. Hardcoded Secrets in Python / TS / JS
    if ([".py", ".ts", ".tsx", ".js", ".jsx"].includes(ext)) {
      const hasTopLevelImportOs = /^\s*import\s+os\b/m.test(file.content);
      lines.forEach((ln, i) => {
        if (ln.trim().startsWith("#") || ln.trim().startsWith("//")) return;
        const sm = ln.match(secretRe);
        if (sm && !ln.includes("os.getenv") && !ln.includes("process.env")) {
          const fid = `local-${idx++}`;
          const envName = "VIBEARMOR_MANAGED_SECRET";
          const fixedLine =
            ext === ".py"
              ? ln.replace(/["'][^"']{12,}["']/, `os.getenv("${envName}", "")`)
              : ln.replace(/["'][^"']{12,}["']/, `(process.env.${envName} || "")`);
          const nextLines = [...lines];
          let targetIdx = i;
          if (ext === ".py" && !hasTopLevelImportOs) {
            // Insert `import os` right after any `from __future__` line (or at line 0) so Python AST & Pylance stay 100% happy!
            let insertAt = 0;
            while (
              insertAt < nextLines.length &&
              (nextLines[insertAt].startsWith("#") ||
                nextLines[insertAt].startsWith('"""') ||
                nextLines[insertAt].startsWith("from __future__") ||
                nextLines[insertAt].trim() === "")
            ) {
              if (nextLines[insertAt].startsWith("from __future__")) {
                insertAt++;
                break;
              }
              insertAt++;
            }
            if (insertAt > 8) insertAt = 0;
            nextLines.splice(insertAt, 0, "import os");
            if (insertAt <= i) targetIdx = i + 1;
          }
          nextLines[targetIdx] = fixedLine;

          findings.push({
            id: fid,
            rule_id: "VA-SEC-001",
            cwe: "CWE-798",
            severity: "CRITICAL",
            title: "Hardcoded credential in source code",
            description: `Detected literal secret (${maskSecrets(sm[1])}); relocate to server environment variable.`,
            file_path: rel,
            line_start: i + 1,
            line_end: i + 1,
          });
          proposals.push({
            finding_id: fid,
            rule_id: "VA-SEC-001",
            cwe: "CWE-798",
            severity: "CRITICAL",
            title: "Relocate hardcoded credential to environment variable",
            file_path: rel,
            line_start: i + 1,
            adoptable: true,
            precision: {
              preservation_pct: 99,
              changed_span_label: `Line ${i + 1}`,
              vulnerable_excerpt: maskSecrets(ln.trim()),
              corrected_excerpt: fixedLine.trim(),
            },
            file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: nextLines.join("\n") }],
          });
        }

        // 3. Python Unsafe YAML / SQL String Interpolation / Subprocess shell=True
        if (ext === ".py") {
          if (/\byaml\.load\s*\([^)]*\)/.test(ln) && !ln.includes("SafeLoader") && !ln.includes("safe_load")) {
            const fid = `local-${idx++}`;
            const fixedLine = ln.replace(/\byaml\.load\s*\(/, "yaml.safe_load(");
            const nextLines = [...lines];
            nextLines[i] = fixedLine;
            findings.push({
              id: fid,
              rule_id: "VA-TNT-004",
              cwe: "CWE-502",
              severity: "HIGH",
              title: "Unsafe yaml.load() allows arbitrary code execution",
              description: "Use yaml.safe_load() to block arbitrary Python object instantiation.",
              file_path: rel,
              line_start: i + 1,
              line_end: i + 1,
            });
            proposals.push({
              finding_id: fid,
              rule_id: "VA-TNT-004",
              cwe: "CWE-502",
              severity: "HIGH",
              title: "Replace yaml.load() with yaml.safe_load()",
              file_path: rel,
              line_start: i + 1,
              adoptable: true,
              precision: {
                preservation_pct: 99.5,
                changed_span_label: `Line ${i + 1}`,
                vulnerable_excerpt: ln.trim(),
                corrected_excerpt: fixedLine.trim(),
              },
              file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: nextLines.join("\n") }],
            });
          }

          if (
            !/#\s*nosec\b/i.test(ln) &&
            (/\.execute\s*\(\s*f["']\s*SELECT\b/i.test(ln) || /\.execute\s*\(\s*["']\s*SELECT\b[^"']*["']\s*\+/i.test(ln))
          ) {
            const fid = `local-${idx++}`;
            let fixedLine = ln;
            const fMatch = ln.match(/^(.*?\.execute\s*\(\s*)f(["'])(.*?)\{([a-zA-Z_][a-zA-Z0-9_.]*)\}(.*?)\2\s*\)(.*)$/);
            if (fMatch) {
              const cleanPre = fMatch[3].replace(/['"]$/, "");
              const cleanPost = fMatch[5].replace(/^['"]/, "");
              fixedLine = `${fMatch[1]}"${cleanPre}?${cleanPost}", (${fMatch[4]},))${fMatch[6]}`;
            }
            const nextLines = [...lines];
            nextLines[i] = fixedLine;
            findings.push({
              id: fid,
              rule_id: "VA-TNT-001",
              cwe: "CWE-89",
              severity: "CRITICAL",
              title: "SQL Injection via unparameterized query string",
              description: "User-controlled variable interpolated directly into SQL execute() call.",
              file_path: rel,
              line_start: i + 1,
              line_end: i + 1,
            });
            if (fixedLine !== ln) {
              proposals.push({
                finding_id: fid,
                rule_id: "VA-TNT-001",
                cwe: "CWE-89",
                severity: "CRITICAL",
                title: "Parameterize SQL query with bound tuple (?)",
                file_path: rel,
                line_start: i + 1,
                adoptable: true,
                precision: {
                  preservation_pct: 99,
                  changed_span_label: `Line ${i + 1}`,
                  vulnerable_excerpt: ln.trim(),
                  corrected_excerpt: fixedLine.trim(),
                },
                file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: nextLines.join("\n") }],
              });
            }
          }

          if (/\bshell\s*=\s*True\b/.test(ln)) {
            const fid = `local-${idx++}`;
            const fixedLine = ln.replace(/\bshell\s*=\s*True\b/, "shell=False");
            const nextLines = [...lines];
            nextLines[i] = fixedLine;
            findings.push({
              id: fid,
              rule_id: "VA-TNT-003",
              cwe: "CWE-78",
              severity: "CRITICAL",
              title: "OS Command Injection sink (shell=True)",
              description: "Subprocess spawned with shell=True permits shell metacharacter injection.",
              file_path: rel,
              line_start: i + 1,
              line_end: i + 1,
            });
            proposals.push({
              finding_id: fid,
              rule_id: "VA-TNT-003",
              cwe: "CWE-78",
              severity: "CRITICAL",
              title: "Enforce shell=False on subprocess invocation",
              file_path: rel,
              line_start: i + 1,
              adoptable: true,
              precision: {
                preservation_pct: 99.5,
                changed_span_label: `Line ${i + 1}`,
                vulnerable_excerpt: ln.trim(),
                corrected_excerpt: fixedLine.trim(),
              },
              file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: nextLines.join("\n") }],
            });
          }
        }
      });
    }

    // 4. SQL Row-Level Security (RLS) checks
    if (ext === ".sql") {
      const tableMatches = [...file.content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([a-zA-Z0-9_]+)/gi)];
      for (const tm of tableMatches) {
        const tbl = tm[1];
        const rlsRe = new RegExp(`ALTER\\s+TABLE\\s+(?:public\\.)?${tbl}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, "i");
        if (!rlsRe.test(file.content)) {
          const lineNo = file.content.slice(0, tm.index || 0).split(/\r?\n/).length;
          const fid = `local-${idx++}`;
          const appendedSql =
            file.content.trimEnd() +
            `\n\nALTER TABLE public.${tbl} ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "vibearmor_${tbl}_owner_iso" ON public.${tbl} FOR ALL TO authenticated USING ((select auth.uid()) IS NOT NULL);\n`;
          findings.push({
            id: fid,
            rule_id: "VA-RLS-001",
            cwe: "CWE-284",
            severity: "CRITICAL",
            title: `PostgreSQL table 'public.${tbl}' missing Row-Level Security (RLS)`,
            description: "PostgREST/Supabase tables without RLS expose rows to unauthenticated callers.",
            file_path: rel,
            line_start: lineNo,
            line_end: lineNo,
          });
          proposals.push({
            finding_id: fid,
            rule_id: "VA-RLS-001",
            cwe: "CWE-284",
            severity: "CRITICAL",
            title: `Enable RLS & authenticated policy on public.${tbl}`,
            file_path: rel,
            line_start: lineNo,
            adoptable: true,
            precision: {
              preservation_pct: 98,
              changed_span_label: `Append RLS policy`,
              vulnerable_excerpt: `CREATE TABLE public.${tbl} (RLS disabled)`,
              corrected_excerpt: `ALTER TABLE public.${tbl} ENABLE ROW LEVEL SECURITY;`,
            },
            file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: appendedSql }],
          });
        }
      }
    }

    // 5. Supply-chain slopsquatting check in package.json
    if (path.basename(rel) === "package.json") {
      lines.forEach((ln, i) => {
        for (const [badPkg, safePkg] of Object.entries(KNOWN_SLOPSQUAT_PKGS)) {
          if (ln.includes(`"${badPkg}"`)) {
            const fid = `local-${idx++}`;
            const fixedLine = ln.replace(`"${badPkg}"`, `"${safePkg}"`);
            const nextLines = [...lines];
            nextLines[i] = fixedLine;
            findings.push({
              id: fid,
              rule_id: "VA-SUP-001",
              cwe: "CWE-829",
              severity: "CRITICAL",
              title: `Hallucinated / slopsquat package '${badPkg}'`,
              description: `AI-hallucinated package name; replace with official '${safePkg}'.`,
              file_path: rel,
              line_start: i + 1,
              line_end: i + 1,
            });
            proposals.push({
              finding_id: fid,
              rule_id: "VA-SUP-001",
              cwe: "CWE-829",
              severity: "CRITICAL",
              title: `Replace '${badPkg}' with verified '${safePkg}'`,
              file_path: rel,
              line_start: i + 1,
              adoptable: true,
              precision: {
                preservation_pct: 99.5,
                changed_span_label: `Line ${i + 1}`,
                vulnerable_excerpt: ln.trim(),
                corrected_excerpt: fixedLine.trim(),
              },
              file_diffs: [{ file_path: rel, created_new: false, before_content: file.content, after_content: nextLines.join("\n") }],
            });
          }
        }
      });
    }
  }

  const envC = findings.filter((f) => f.rule_id.startsWith("VA-ENV")).length;
  const rlsC = findings.filter((f) => f.rule_id.startsWith("VA-RLS")).length;
  const keyC = findings.filter((f) => f.rule_id.startsWith("VA-SEC")).length;
  const injC = findings.filter((f) => f.rule_id.startsWith("VA-TNT")).length;
  const supC = findings.filter((f) => f.rule_id.startsWith("VA-SUP")).length;
  const score = Math.max(8, 100 - findings.length * 16);

  return {
    session_id: "offline-local-engine",
    engine_mode: "builtin_offline",
    ready_to_push: findings.length === 0,
    ready_to_deploy: findings.length === 0,
    security_score: findings.length === 0 ? 100 : score,
    blocking_count: findings.length,
    node_count: files.length,
    edge_count: Math.max(0, files.length - 1),
    checks: {
      dotenv_hygiene: { passed: envC === 0, count: envC, label: ".env Variables & Gitignore Push Protection" },
      supabase_rls: { passed: rlsC === 0, count: rlsC, label: "Supabase / Postgres Row-Level Access Rules" },
      browser_keys: { passed: keyC === 0, count: keyC, label: "Source & Browser Private API Key Isolation" },
      injections_payments: { passed: injC === 0, count: injC, label: "SQL/Command/YAML Injection & Webhook Guards" },
      supply_chain: { passed: supC === 0, count: supC, label: "AI-Hallucinated Packages & Dependencies" },
    },
    findings,
    proposals,
  };
}

function detectEditorName(): string {
  const appName = (vscode.env.appName || "").toLowerCase();
  if (appName.includes("cursor")) return "Cursor";
  if (appName.includes("windsurf")) return "Windsurf";
  if (appName.includes("antigravity")) return "Antigravity";
  if (appName.includes("codium")) return "VSCodium";
  if (appName.includes("trae")) return "Trae";
  return "VS Code";
}

function detectGitBranch(repoDir: string): string {
  try {
    const sym = execFileSync("git", ["symbolic-ref", "--short", "HEAD"], {
      cwd: repoDir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (sym) return sym;
  } catch {
    // detached HEAD or unborn
  }
  try {
    const rev = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: repoDir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (rev && rev !== "HEAD") return rev;
  } catch {
    // ignore
  }
  return "main";
}

function detectGitRemoteOrigin(repoDir: string): string {
  try {
    return execFileSync("git", ["remote", "get-url", "origin"], {
      cwd: repoDir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "";
  }
}

function inspectWorkspaceGitStatus(workspaceRoot: string, preferredRepoDir?: string): GitRepoStatus {
  const targetDir = preferredRepoDir && fs.existsSync(preferredRepoDir) ? preferredRepoDir : workspaceRoot;
  if (isValidGitWorktree(targetDir)) {
    const top = getGitTopLevel(targetDir) || targetDir;
    return {
      isGitRepo: true,
      repoDir: top,
      branch: detectGitBranch(top),
      remoteUrl: detectGitRemoteOrigin(top),
      childRepos: [],
    };
  }
  const childRepos = findChildGitRepos(workspaceRoot);
  if (childRepos.length === 1) {
    const sub = childRepos[0];
    return {
      isGitRepo: true,
      repoDir: sub,
      branch: detectGitBranch(sub),
      remoteUrl: detectGitRemoteOrigin(sub),
      childRepos,
    };
  }
  return {
    isGitRepo: false,
    repoDir: workspaceRoot,
    branch: "main",
    remoteUrl: "",
    childRepos,
  };
}

function collectWorkspaceFiles(rootDir: string): Array<{ path: string; content: string }> {
  const collected: Array<{ path: string; content: string }> = [];
  function walk(current: string) {
    if (collected.length >= 240) return;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      if (ent.isDirectory()) {
        if (!IGNORED_DIRS.has(ent.name)) {
          walk(path.join(current, ent.name));
        }
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (SCANNABLE_EXTS.has(ext) || SCANNABLE_NAMES.has(ent.name) || ent.name.startsWith(".env")) {
          const full = path.join(current, ent.name);
          try {
            const stat = fs.statSync(full);
            if (stat.size <= 350_000) {
              const rel = path.relative(rootDir, full).split(path.sep).join("/");
              collected.push({ path: rel, content: fs.readFileSync(full, "utf-8") });
            }
          } catch {
            // ignore unreadable file
          }
        }
      }
    }
  }
  walk(rootDir);
  return collected;
}

function httpJson<T>(method: "GET" | "POST", serverUrl: string, endpoint: string, bodyObj?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    let target: URL;
    try {
      target = new URL(endpoint, serverUrl);
    } catch (e) {
      reject(e);
      return;
    }
    const payload = bodyObj !== undefined ? Buffer.from(JSON.stringify(bodyObj), "utf-8") : undefined;
    const lib = target.protocol === "https:" ? https : http;
    const headers: Record<string, string | number> = {};
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = payload.length;
    }
    const req = lib.request(target, { method, headers, timeout: 6500 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (d) => chunks.push(Buffer.from(d)));
      res.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf-8");
        if ((res.statusCode || 500) >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${raw.slice(0, 200)}`));
          return;
        }
        try {
          resolve(JSON.parse(raw) as T);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on("timeout", () => req.destroy(new Error("Connection timeout")));
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function escHtml(s: string): string {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function activate(context: vscode.ExtensionContext) {
  const diagnostics = vscode.languages.createDiagnosticCollection("vibearmor");
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = "$(shield) VibeArmor: Check Push Gate";
  statusBar.command = "vibearmor.verifyReadiness";
  statusBar.show();

  const virtualDocs = new Map<string, string>();
  const previewProvider: vscode.TextDocumentContentProvider = {
    provideTextDocumentContent(uri: vscode.Uri): string {
      return virtualDocs.get(uri.path) || "";
    },
  };

  let latestResult: ReadinessResponse | null = null;
  let pairedProjectId = "";
  let selectedGitRepoDir = "";
  let webviewRef: vscode.WebviewView | null = null;
  let hookInstalled = false;
  let saveDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  const quickFixProvider: vscode.CodeActionProvider = {
    provideCodeActions(document: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder || !latestResult) return [];
      const relPath = path.relative(folder.uri.fsPath, document.uri.fsPath).split(path.sep).join("/");
      const actions: vscode.CodeAction[] = [];

      for (const prop of latestResult.proposals || []) {
        if (!prop.adoptable || prop.file_path !== relPath) continue;
        const propLine0 = Math.max(0, (prop.line_start || 1) - 1);
        if (propLine0 < range.start.line - 2 || propLine0 > range.end.line + 2) continue;

        const fd = prop.file_diffs.find((d) => d.file_path === relPath && !d.created_new);
        if (!fd) continue;

        const patchSpan = computeMinimalLinePatch(document.getText(), fd.after_content);
        const maxLine = Math.max(0, document.lineCount - 1);
        const safeStart = Math.min(patchSpan.startLine, maxLine);
        const safeEnd = Math.min(patchSpan.endLine, maxLine);
        const exactRange = new vscode.Range(
          safeStart,
          0,
          safeEnd,
          document.lineAt(safeEnd).text.length
        );

        const action = new vscode.CodeAction(
          `🛡️ VibeArmor Surgical Fix: [${prop.rule_id}] ${prop.title}`,
          vscode.CodeActionKind.QuickFix
        );
        const wsEdit = new vscode.WorkspaceEdit();
        wsEdit.replace(document.uri, exactRange, patchSpan.replacementText);
        action.edit = wsEdit;
        action.isPreferred = true;
        actions.push(action);
      }
      return actions;
    },
  };

  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider("vibearmor-fixed", previewProvider),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, quickFixProvider, {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }),
    diagnostics,
    statusBar
  );

  function getServerUrl(): string {
    return vscode.workspace.getConfiguration("vibearmor").get<string>("serverUrl", "http://127.0.0.1:8000");
  }

  function getPairToken(): string {
    return vscode.workspace.getConfiguration("vibearmor").get<string>("pairToken", "").trim();
  }

  function getSavedGitHubUrl(): string {
    return vscode.workspace.getConfiguration("vibearmor").get<string>("githubRepoUrl", "").trim();
  }

  /** Initialize a real Git worktree (`git init -b main` + safe `.gitignore`) if missing or broken! */
  async function initializeGitRepoAt(dir: string): Promise<boolean> {
    try {
      ensureSafeGitignore(dir);
      try {
        await runGitAsync(dir, ["init", "-b", "main"]);
      } catch {
        await runGitAsync(dir, ["init"]);
        try {
          await runGitAsync(dir, ["checkout", "-B", "main"]);
        } catch {
          // ignore on older Git before first commit
        }
      }
      selectedGitRepoDir = dir;
      renderWebview();
      return true;
    } catch (err: unknown) {
      vscode.window.showErrorMessage(
        `VibeArmor: Could not initialize Git repository in '${dir}': ${err instanceof Error ? err.message : String(err)}`
      );
      return false;
    }
  }

  /** Resolve active Git repo OR offer 1-Click `git init` when folder has no `.git` (fixes image-12!). */
  async function resolveOrInitGitRepo(workspaceRoot: string): Promise<string | null> {
    if (selectedGitRepoDir && isValidGitWorktree(selectedGitRepoDir)) {
      return getGitTopLevel(selectedGitRepoDir) || selectedGitRepoDir;
    }
    if (isValidGitWorktree(workspaceRoot)) {
      const top = getGitTopLevel(workspaceRoot) || workspaceRoot;
      selectedGitRepoDir = top;
      return top;
    }

    const childRepos = findChildGitRepos(workspaceRoot);
    if (childRepos.length > 0) {
      const subNames = childRepos.map((c) => path.basename(c));
      const choice = await vscode.window.showInformationMessage(
        `'${path.basename(workspaceRoot)}' is not a Git repository at root, but subfolder '${subNames[0]}' has Git initialized. Which folder do you want to push?`,
        { modal: true },
        `Push Subfolder (${subNames[0]})`,
        `Initialize Git at Root (${path.basename(workspaceRoot)})`
      );
      if (!choice) return null;
      if (choice.startsWith("Push Subfolder")) {
        selectedGitRepoDir = childRepos[0];
        renderWebview();
        return childRepos[0];
      }
      const ok = await initializeGitRepoAt(workspaceRoot);
      return ok ? workspaceRoot : null;
    }

    const initChoice = await vscode.window.showInformationMessage(
      `'${path.basename(workspaceRoot)}' does not have Git initialized yet (.git missing).\n\nInitialize Git (branch 'main'), auto-protect .env & .venv in .gitignore, and connect your GitHub repository now?`,
      { modal: true },
      "Initialize Git & Connect GitHub"
    );
    if (initChoice !== "Initialize Git & Connect GitHub") {
      return null;
    }
    const ok = await initializeGitRepoAt(workspaceRoot);
    return ok ? workspaceRoot : null;
  }

  async function ensureGitAuthorIdentity(repoDir: string): Promise<boolean> {
    let userName = "";
    let userEmail = "";
    try {
      userName = (await runGitAsync(repoDir, ["config", "user.name"])).stdout.trim();
    } catch {
      userName = "";
    }
    try {
      userEmail = (await runGitAsync(repoDir, ["config", "user.email"])).stdout.trim();
    } catch {
      userEmail = "";
    }
    if (userName && userEmail) return true;

    const enteredName = await vscode.window.showInputBox({
      title: "Git Commit Author Name (One-Time Setup)",
      prompt: "Git needs an author name for commits in this repository",
      value: userName || "VibeArmor Developer",
    });
    if (!enteredName) return false;

    const enteredEmail = await vscode.window.showInputBox({
      title: "Git Commit Author Email (One-Time Setup)",
      prompt: "Git needs an author email for commits in this repository",
      value: userEmail || "developer@users.noreply.github.com",
    });
    if (!enteredEmail) return false;

    await runGitAsync(repoDir, ["config", "user.name", enteredName.trim()]);
    await runGitAsync(repoDir, ["config", "user.email", enteredEmail.trim()]);
    return true;
  }

  async function ensureGitRemoteOrigin(repoDir: string, forcePrompt = false): Promise<string | null> {
    const existingOrigin = detectGitRemoteOrigin(repoDir);
    if (existingOrigin && !forcePrompt) {
      return existingOrigin;
    }

    const defaultVal = existingOrigin || getSavedGitHubUrl();
    const entered = await vscode.window.showInputBox({
      title: "Connect Target GitHub Repository (origin)",
      prompt: "Paste your GitHub repository URL (e.g. https://github.com/your-username/your-repo)",
      value: defaultVal,
      placeHolder: "https://github.com/owner/repository",
      ignoreFocusOut: true,
    });
    if (!entered || !entered.trim()) {
      return null;
    }

    const normalized = normalizeGitHubRemoteUrl(entered);
    if (existingOrigin) {
      await runGitAsync(repoDir, ["remote", "set-url", "origin", normalized]);
    } else {
      await runGitAsync(repoDir, ["remote", "add", "origin", normalized]);
    }
    await vscode.workspace
      .getConfiguration("vibearmor")
      .update("githubRepoUrl", normalized, vscode.ConfigurationTarget.Workspace);
    renderWebview();
    return normalized;
  }

  function launchInteractiveTerminalPush(repoDir: string, branch: string) {
    const term = vscode.window.createTerminal({
      name: "VibeArmor Safe Git Push",
      cwd: repoDir,
    });
    term.show();
    term.sendText(`git status -sb`);
    term.sendText(`git push -u origin ${branch}`);
  }

  function publishEditorDiagnostics(folderPath: string, findings: DiagnosticItem[]) {
    diagnostics.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const f of findings) {
      const fullPath = path.join(folderPath, f.file_path);
      let lineLen = 120;
      const line = Math.max(0, (f.line_start || 1) - 1);
      const endLine = Math.max(line, (f.line_end || f.line_start || 1) - 1);
      try {
        if (fs.existsSync(fullPath)) {
          const docLines = fs.readFileSync(fullPath, "utf-8").split(/\r?\n/);
          lineLen = (docLines[Math.min(endLine, docLines.length - 1)] || "").length || 80;
        }
      } catch {
        // keep fallback line length
      }
      const range = new vscode.Range(line, 0, endLine, lineLen);
      const sev =
        f.severity === "CRITICAL" || f.severity === "HIGH"
          ? vscode.DiagnosticSeverity.Error
          : vscode.DiagnosticSeverity.Warning;
      const cweLbl = f.cwe ? ` (${f.cwe})` : "";
      const diag = new vscode.Diagnostic(
        range,
        `[${f.rule_id}${cweLbl}] ${maskSecrets(f.title)}: ${maskSecrets(f.description)}`,
        sev
      );
      diag.source = "VibeArmor Gate";
      diag.code = f.rule_id;
      const list = byFile.get(f.file_path) || [];
      list.push(diag);
      byFile.set(f.file_path, list);
    }
    for (const [rel, list] of byFile.entries()) {
      diagnostics.set(vscode.Uri.file(path.join(folderPath, rel)), list);
    }
  }

  function renderWebview() {
    if (!webviewRef) return;
    const folder = vscode.workspace.workspaceFolders?.[0];
    const gitState: GitRepoStatus | null = folder
      ? inspectWorkspaceGitStatus(folder.uri.fsPath, selectedGitRepoDir)
      : null;

    const token = getPairToken();
    const engineBadge =
      latestResult?.engine_mode === "builtin_offline"
        ? `<span style="background:#FEF3C7;color:#92400E;border:1px solid #FDE68A;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700;">⚡ Local Standalone Engine</span>`
        : token
        ? `<span style="background:#EEF2FF;color:#4338CA;border:1px solid #C7D2FE;padding:2px 7px;border-radius:999px;font-size:10px;font-weight:700;">⇄ Studio Paired</span>`
        : `<button onclick="send('pair')" style="background:#EEF2FF;color:#4338CA;border:1px solid #C7D2FE;padding:2px 8px;border-radius:999px;font-size:10px;font-weight:700;cursor:pointer;">+ Pair Web Studio</button>`;

    const shortRemote = gitState?.remoteUrl
      ? (extractGitHubWebRepoUrl(gitState.remoteUrl) || gitState.remoteUrl).replace(/^https?:\/\/github\.com\//i, "")
      : "";

    const gitCardHtml = gitState
      ? `<div style="background:#fff;border:1px solid #E2E8F0;border-radius:9px;padding:8px 9px;margin-bottom:9px;font-size:10.5px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
            <strong style="color:#0F172A;">Git Repository Target</strong>
            <button onclick="send('cfgRemote')" style="background:none;border:none;color:#4F46E5;font-size:10px;font-weight:700;cursor:pointer;padding:0;">
              ${shortRemote ? "Change URL ⚙" : "+ Set GitHub URL"}
            </button>
          </div>
          <div style="color:${gitState.isGitRepo ? "#059669" : "#B45309"};font-weight:600;">
            ${
              gitState.isGitRepo
                ? `✔ Git Ready (${escHtml(path.basename(gitState.repoDir))} · branch: ${escHtml(gitState.branch)})`
                : `⚠ No .git yet — clicking Safe Push will auto-init Git & .gitignore!`
            }
          </div>
          <div style="color:#475569;font-family:monospace;font-size:10px;margin-top:2px;word-break:break-all;">
            ${shortRemote ? `origin → ${escHtml(shortRemote)}` : "origin → (prompts on push)"}
          </div>
        </div>`
      : "";

    if (!latestResult) {
      webviewRef.webview.html = `<!DOCTYPE html><html><body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:12px;color:#0F172A;background:#F8FAFC;">
        <div style="background:#fff;border:1px solid #E2E8F0;border-radius:10px;padding:12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <strong style="font-size:13px;">🛡️ VibeArmor Push Gate</strong>
            ${engineBadge}
          </div>
          <p style="font-size:11.5px;color:#475569;margin:0 0 10px;line-height:1.45;">
            Works <strong>100% standalone offline</strong> inside ${escHtml(detectEditorName())} AND syncs live with VibeArmor Studio when paired.
          </p>
          ${gitCardHtml}
          <button onclick="send('verify')" style="width:100%;padding:8px 10px;background:#4F46E5;color:#fff;border:none;border-radius:8px;font-weight:700;font-size:12px;cursor:pointer;margin-bottom:6px;">
            Scan Workspace &amp; Verify Push Gate
          </button>
          <button onclick="send('hook')" style="width:100%;padding:7px 10px;background:#F1F5F9;color:#1E293B;border:1px solid #CBD5E1;border-radius:8px;font-weight:600;font-size:11px;cursor:pointer;">
            Install Staged Git Pre-Commit &amp; Push Gate
          </button>
        </div>
        <script>
          const vscode = acquireVsCodeApi();
          function send(cmd, data) { vscode.postMessage(Object.assign({ cmd }, data || {})); }
        </script>
      </body></html>`;
      return;
    }

    const ready = latestResult.ready_to_push;
    const bannerBg = ready ? "#ECFDF5" : "#FFF1F2";
    const bannerBorder = ready ? "#A7F3D0" : "#FECDD3";
    const bannerText = ready ? "#065F46" : "#9F1239";
    const verdict = ready
      ? `✓ READY TO PUSH & DEPLOY (${latestResult.security_score}/100)`
      : `🛑 PUSH & DEPLOY BLOCKED (${latestResult.blocking_count} Open Threats)`;

    const checkRows = Object.values(latestResult.checks || {})
      .map(
        (c) => `
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;padding:5px 0;border-bottom:1px solid #F1F5F9;">
          <span style="color:#334155;">${c.passed ? "✅" : "❌"} ${escHtml(c.label)}</span>
          <strong style="color:${c.passed ? "#059669" : "#E11D48"};">${c.passed ? "PASS" : c.count + " open"}</strong>
        </div>`
      )
      .join("");

    const adoptableProps = (latestResult.proposals || []).filter((p) => p.adoptable);
    const proposalCards = adoptableProps
      .map((p) => {
        const vulnEx = escHtml(maskSecrets(p.precision?.vulnerable_excerpt || "")).slice(0, 220);
        const corrEx = escHtml(maskSecrets(p.precision?.corrected_excerpt || "")).slice(0, 220);
        const presPct = p.precision?.preservation_pct ?? 99;
        return `
        <div style="border:1px solid #E2E8F0;border-radius:8px;padding:8px;margin-top:8px;background:#fff;">
          <label style="display:flex;align-items:flex-start;gap:6px;cursor:pointer;">
            <input type="checkbox" class="prop-cb" value="${escHtml(p.finding_id)}" checked style="margin-top:2px;" />
            <div style="flex:1;min-width:0;">
              <div style="font-size:11px;font-weight:700;color:#0F172A;">[${escHtml(p.rule_id)}] ${escHtml(p.title)}</div>
              <div style="font-size:10px;color:#64748B;font-family:monospace;">${escHtml(p.file_path)}:${p.line_start} · ${presPct}% preserved</div>
            </div>
          </label>
          <div style="margin-top:6px;background:#FFF1F2;border:1px solid #FECDD3;border-radius:5px;padding:5px;font-family:monospace;font-size:9.5px;color:#881337;white-space:pre-wrap;overflow-x:auto;">- ${vulnEx}</div>
          <div style="margin-top:4px;background:#ECFDF5;border:1px solid #A7F3D0;border-radius:5px;padding:5px;font-family:monospace;font-size:9.5px;color:#065F46;white-space:pre-wrap;overflow-x:auto;">+ ${corrEx}</div>
          <button onclick="send('diff', { id: '${escHtml(p.finding_id)}' })" style="margin-top:5px;background:none;border:none;color:#4F46E5;font-size:10.5px;font-weight:700;cursor:pointer;padding:0;">
            Open Side-by-Side Split Diff in Editor ↗
          </button>
        </div>`;
      })
      .join("");

    webviewRef.webview.html = `<!DOCTYPE html><html><body style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;padding:10px;color:#0F172A;background:#F8FAFC;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <span style="font-size:11px;font-weight:700;color:#475569;">${escHtml(detectEditorName())} v3.6</span>
        ${engineBadge}
      </div>

      <div style="padding:10px;border-radius:9px;background:${bannerBg};border:1px solid ${bannerBorder};color:${bannerText};font-weight:800;font-size:11.5px;margin-bottom:9px;">
        ${verdict}
      </div>

      ${gitCardHtml}

      <div style="background:#fff;border:1px solid #E2E8F0;border-radius:9px;padding:9px;margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <strong style="font-size:11px;color:#0F172A;">5-Point Pre-Push Gate</strong>
          <button onclick="send('cfgServer')" style="background:none;border:none;color:#4F46E5;font-size:10px;font-weight:700;cursor:pointer;padding:0;">
            Server Config ⚙
          </button>
        </div>
        ${checkRows}
      </div>

      ${
        adoptableProps.length > 0
          ? `<div style="margin-bottom:10px;">
              <div style="font-size:11px;font-weight:800;color:#0F172A;">Surgical Fixes (${adoptableProps.length}) — 💡 Quick Fix Active</div>
              ${proposalCards}
              <button onclick="adoptChecked()" style="margin-top:8px;width:100%;padding:8px;background:#4F46E5;color:#fff;border:none;border-radius:8px;font-weight:700;font-size:11.5px;cursor:pointer;">
                Adopt Selected Surgical Fixes
              </button>
            </div>`
          : ""
      }

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:6px;">
        <button onclick="send('verify')" style="padding:7px;background:#fff;color:#0F172A;border:1px solid #CBD5E1;border-radius:7px;font-weight:600;font-size:11px;cursor:pointer;">
          Re-Scan Folder
        </button>
        <button onclick="send('hook')" style="padding:7px;background:#fff;color:#0F172A;border:1px solid #CBD5E1;border-radius:7px;font-weight:600;font-size:11px;cursor:pointer;">
          ${hookInstalled ? "✓ Git Hook Active" : "Install Push Hook"}
        </button>
      </div>

      <button onclick="send('safePush')" style="width:100%;padding:9px;background:${ready ? "#059669" : "#94A3B8"};color:#fff;border:none;border-radius:8px;font-weight:800;font-size:12px;cursor:pointer;">
        ${ready ? "🚀 1-Click Safe Push to GitHub" : "🔒 Push Locked Until Threats Fixed"}
      </button>

      ${
        ready
          ? `<button onclick="send('termPush')" style="margin-top:6px;width:100%;padding:6px;background:#fff;color:#334155;border:1px solid #CBD5E1;border-radius:7px;font-weight:600;font-size:10.5px;cursor:pointer;">
              Push via Integrated Terminal (Interactive Git Auth) ↗
            </button>`
          : ""
      }

      <script>
        const vscode = acquireVsCodeApi();
        function send(cmd, data) { vscode.postMessage(Object.assign({ cmd }, data || {})); }
        function adoptChecked() {
          const ids = Array.from(document.querySelectorAll('.prop-cb:checked')).map(el => el.value);
          send('adoptSelected', { ids });
        }
      </script>
    </body></html>`;
  }

  async function syncAndVerify(silent = false) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      if (!silent) vscode.window.showWarningMessage("VibeArmor: Open a project folder first.");
      return;
    }
    const serverUrl = getServerUrl();
    const pairToken = getPairToken();
    const files = collectWorkspaceFiles(folder.uri.fsPath);
    const gitSt = inspectWorkspaceGitStatus(folder.uri.fsPath, selectedGitRepoDir);
    const branch = gitSt.branch;

    statusBar.text = "$(sync~spin) VibeArmor: Scanning...";
    try {
      if (pairToken) {
        const syncRes = await httpJson<{ project_id: string }>("POST", serverUrl, "/api/extension/pair/sync-up", {
          pair_token: pairToken,
          editor: detectEditorName(),
          workspace_name: folder.name,
          local_path: folder.uri.fsPath,
          branch,
          files,
        });
        pairedProjectId = syncRes.project_id || pairedProjectId;
      }

      const res = await httpJson<ReadinessResponse>("POST", serverUrl, "/api/extension/verify-readiness", {
        editor: detectEditorName(),
        workspace_name: folder.name,
        branch,
        project_id: pairedProjectId || undefined,
        files: pairedProjectId ? [] : files,
        include_proposals: true,
      });
      res.engine_mode = "studio_server";
      latestResult = res;
      if (res.project_id) pairedProjectId = res.project_id;
    } catch {
      latestResult = runBuiltInLocalSecurityAudit(files);
    }

    publishEditorDiagnostics(folder.uri.fsPath, latestResult.findings || []);
    if (latestResult.ready_to_push) {
      statusBar.text = `$(shield) VibeArmor: Ready (${latestResult.security_score}/100)`;
    } else {
      statusBar.text = `$(error) VibeArmor: Blocked (${latestResult.blocking_count} Threats)`;
    }
    renderWebview();
  }

  async function pollPendingWebApprovals() {
    const token = getPairToken();
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!token || !folder) return;
    try {
      const data = await httpJson<{ pending_files?: Record<string, string> }>(
        "GET",
        getServerUrl(),
        `/api/extension/pair/${encodeURIComponent(token)}/pending-fixes`
      );
      const pending = data.pending_files || {};
      const relPaths = Object.keys(pending);
      if (relPaths.length === 0) return;

      const applied: string[] = [];
      for (const rel of relPaths) {
        const cleanRel = rel.replace(/^\/+/, "").replace(/\.\./g, "_");
        const target = path.join(folder.uri.fsPath, cleanRel);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, pending[rel], "utf-8");
        applied.push(cleanRel);
      }
      await httpJson("POST", getServerUrl(), `/api/extension/pair/${encodeURIComponent(token)}/ack-fixes`, {
        applied_files: applied,
      });
      vscode.window.showInformationMessage(
        `VibeArmor Two-Way Sync: Applied ${applied.length} surgical fix(es) approved in Web Studio!`
      );
      await syncAndVerify(true);
    } catch {
      // ignore background poll errors when offline
    }
  }

  const pollTimer = setInterval(pollPendingWebApprovals, 5000);
  context.subscriptions.push({ dispose: () => clearInterval(pollTimer) });

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      const auto = vscode.workspace.getConfiguration("vibearmor").get<boolean>("autoSyncOnSave", true);
      if (!auto) return;
      if (saveDebounceTimer) clearTimeout(saveDebounceTimer);
      saveDebounceTimer = setTimeout(() => {
        syncAndVerify(true);
      }, 450);
    })
  );

  async function openProposalSplitDiff(findingId?: string) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder || !latestResult) return;
    const prop =
      latestResult.proposals.find((p) => p.finding_id === findingId) ||
      latestResult.proposals.find((p) => p.adoptable);
    if (!prop) return;
    const diff = prop.file_diffs.find((d) => !d.created_new) || prop.file_diffs[0];
    if (!diff) return;
    const fixedUri = vscode.Uri.parse(`vibearmor-fixed:/${diff.file_path}`);
    virtualDocs.set(`/${diff.file_path}`, diff.after_content);
    const origUri = vscode.Uri.file(path.join(folder.uri.fsPath, diff.file_path));
    if (fs.existsSync(origUri.fsPath)) {
      await vscode.commands.executeCommand(
        "vscode.diff",
        origUri,
        fixedUri,
        `VibeArmor Surgical Diff: ${diff.file_path} (Vulnerable ↔ Corrected)`
      );
    }
  }

  async function adoptSelectedSurgicalFixes(selectedIds?: string[]) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder || !latestResult) {
      await syncAndVerify();
      if (!folder || !latestResult) return;
    }
    const adoptable = latestResult.proposals.filter(
      (p) => p.adoptable && (!selectedIds || selectedIds.includes(p.finding_id))
    );
    if (adoptable.length === 0) {
      vscode.window.showInformationMessage("VibeArmor: Select at least one surgical fix to adopt.");
      return;
    }

    const confirm = await vscode.window.showInformationMessage(
      `Adopt ${adoptable.length} surgical VibeArmor fix(es)? Exact line ranges will be updated; clean files stay untouched.`,
      { modal: true },
      "Adopt Surgical Fixes"
    );
    if (confirm !== "Adopt Surgical Fixes") return;

    const wsEdit = new vscode.WorkspaceEdit();
    for (const prop of adoptable) {
      for (const fd of prop.file_diffs) {
        const fullTarget = path.join(folder.uri.fsPath, fd.file_path);
        const uri = vscode.Uri.file(fullTarget);
        if (!fd.created_new && fs.existsSync(fullTarget)) {
          const doc = await vscode.workspace.openTextDocument(uri);
          const span = computeMinimalLinePatch(doc.getText(), fd.after_content);
          const maxLine = Math.max(0, doc.lineCount - 1);
          const sL = Math.min(span.startLine, maxLine);
          const eL = Math.min(span.endLine, maxLine);
          wsEdit.replace(uri, new vscode.Range(sL, 0, eL, doc.lineAt(eL).text.length), span.replacementText);
        } else {
          fs.mkdirSync(path.dirname(fullTarget), { recursive: true });
          fs.writeFileSync(fullTarget, fd.after_content, "utf-8");
        }
      }
    }
    await vscode.workspace.applyEdit(wsEdit);
    await vscode.workspace.saveAll(false);
    vscode.window.showInformationMessage(`VibeArmor: Adopted ${adoptable.length} surgical fix(es). Re-verifying gate...`);
    await syncAndVerify();
  }

  async function installGitPushGate() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    // Always ensure a real valid Git worktree FIRST (never create `.git/hooks` without `.git/HEAD`!)
    const repoDir = await resolveOrInitGitRepo(folder.uri.fsPath);
    if (!repoDir) return;

    const hooksDir = path.join(repoDir, ".git", "hooks");
    const vaDir = path.join(repoDir, ".vibearmor");
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.mkdirSync(vaDir, { recursive: true });

    const bundledBridge = path.join(context.extensionPath, "vibearmor_bridge.py");
    if (fs.existsSync(bundledBridge)) {
      fs.copyFileSync(bundledBridge, path.join(vaDir, "vibearmor_bridge.py"));
    }

    const preCommitScript = `#!/usr/bin/env sh
# VibeArmor Staged-Files Git Pre-Commit Security Gate
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)
if [ -z "$STAGED_FILES" ]; then
  exit 0
fi
echo "[VibeArmor Pre-Commit] Scanning staged files..."
for f in $STAGED_FILES; do
  case "$f" in
    .env|.env.local|.env.production)
      echo "🚫 COMMIT BLOCKED — Reason: Raw secret file '$f' is staged for Git commit!"
      exit 1
      ;;
  esac
  if [ -f "$f" ]; then
    if grep -Eq "(sk_live_|sk_test_|ghp_[A-Za-z0-9]{20}|github_pat_[A-Za-z0-9_]{20}|AIza[0-9A-Za-z_-]{20})" "$f" 2>/dev/null; then
      echo "🚫 COMMIT BLOCKED — Reason: Hardcoded API secret detected in staged file '$f'!"
      exit 1
    fi
  fi
done
if command -v vibearmor >/dev/null 2>&1; then
  vibearmor guard --staged .
fi
exit 0
`;
    fs.writeFileSync(path.join(hooksDir, "pre-commit"), preCommitScript, { mode: 0o755 });
    fs.writeFileSync(path.join(hooksDir, "pre-push"), preCommitScript, { mode: 0o755 });
    hookInstalled = true;
    renderWebview();
    vscode.window.showInformationMessage(`VibeArmor: Staged Git pre-commit & pre-push gate installed in '${path.basename(repoDir)}'!`);
  }

  async function configureGitRemoteFlow() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;
    const repoDir = await resolveOrInitGitRepo(folder.uri.fsPath);
    if (!repoDir) return;
    const remote = await ensureGitRemoteOrigin(repoDir, true);
    if (remote) {
      vscode.window.showInformationMessage(`VibeArmor: Target GitHub repository set to ${remote}`);
    }
  }

  async function stageSafeCommitInRepo(repoDir: string): Promise<string> {
    ensureSafeGitignore(repoDir);
    await ensureGitAuthorIdentity(repoDir);

    await runGitAsync(repoDir, ["add", "-A"]);
    for (const secFile of [".env", ".env.local", ".env.production"]) {
      try {
        await runGitAsync(repoDir, ["rm", "--cached", "--ignore-unmatch", secFile]);
      } catch {
        // ignore
      }
    }

    const st = (await runGitAsync(repoDir, ["status", "--porcelain"])).stdout.trim();
    if (st) {
      await runGitAsync(repoDir, ["commit", "-m", "chore(security): apply VibeArmor verified updates"]);
    } else {
      // Ensure at least 1 commit exists (if brand-new repo had nothing staged yet)
      try {
        await runGitAsync(repoDir, ["rev-parse", "--verify", "HEAD"]);
      } catch {
        await runGitAsync(repoDir, ["commit", "--allow-empty", "-m", "chore(security): initial VibeArmor verified commit"]);
      }
    }
    return detectGitBranch(repoDir);
  }

  async function safePushToGitHub(useTerminalDirectly = false) {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showWarningMessage("VibeArmor: Open a project folder first.");
      return;
    }

    await syncAndVerify();
    if (!latestResult || !latestResult.ready_to_push) {
      const cnt = latestResult?.blocking_count ?? "multiple";
      const pick = await vscode.window.showErrorMessage(
        `STOP — VibeArmor Hard Gate blocked Git Push: ${cnt} open security threat(s) remain in '${folder.name}'.`,
        "Review & Adopt Surgical Fixes"
      );
      if (pick === "Review & Adopt Surgical Fixes") {
        await openProposalSplitDiff();
      }
      return;
    }

    // 1. Resolve or auto-initialize Git repository (fixes `fatal: not a git repository`!)
    const repoDir = await resolveOrInitGitRepo(folder.uri.fsPath);
    if (!repoDir) return;

    // 2. Ensure `origin` remote URL is configured
    const remoteUrl = await ensureGitRemoteOrigin(repoDir, false);
    if (!remoteUrl) {
      vscode.window.showWarningMessage("VibeArmor: Push cancelled — set your GitHub repository URL to push.");
      return;
    }

    const webRepoUrl = extractGitHubWebRepoUrl(remoteUrl);
    const branchPreview = detectGitBranch(repoDir);

    if (useTerminalDirectly) {
      try {
        const br = await stageSafeCommitInRepo(repoDir);
        launchInteractiveTerminalPush(repoDir, br);
      } catch (err: unknown) {
        vscode.window.showErrorMessage(`VibeArmor commit error: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    const confirm = await vscode.window.showInformationMessage(
      `VibeArmor Verified (${latestResult.security_score}/100 · 0 Threats).\n\nCommit safe files (excluding .env & .venv) and push '${path.basename(repoDir)}' (${branchPreview}) to ${remoteUrl}?`,
      { modal: true },
      "Safe Commit & Push",
      "Push as New PR Branch",
      "Change GitHub URL"
    );
    if (!confirm) return;
    if (confirm === "Change GitHub URL") {
      await ensureGitRemoteOrigin(repoDir, true);
      return;
    }

    try {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "VibeArmor: Committing & pushing verified code to GitHub...",
          cancellable: false,
        },
        async () => {
          let targetBranch = await stageSafeCommitInRepo(repoDir);
          if (confirm === "Push as New PR Branch") {
            targetBranch = `vibearmor/safe-push-${Math.floor(Date.now() / 1000)}`;
            await runGitAsync(repoDir, ["checkout", "-B", targetBranch]);
          }
          await runGitAsync(repoDir, ["push", "-u", "origin", targetBranch]);

          renderWebview();
          const openLabel = confirm === "Push as New PR Branch" ? "Open Pull Request on GitHub ↗" : "Open Repository on GitHub ↗";
          const targetLink =
            confirm === "Push as New PR Branch" && webRepoUrl
              ? `${webRepoUrl}/compare/${encodeURIComponent(targetBranch)}?expand=1`
              : webRepoUrl;

          if (targetLink) {
            vscode.window
              .showInformationMessage(`✅ VibeArmor: Successfully pushed '${targetBranch}' to GitHub!`, openLabel)
              .then((sel) => {
                if (sel === openLabel) {
                  vscode.env.openExternal(vscode.Uri.parse(targetLink));
                }
              });
          } else {
            vscode.window.showInformationMessage(`✅ VibeArmor: Successfully pushed '${targetBranch}' to ${remoteUrl}!`);
          }
        }
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      const lower = msg.toLowerCase();

      // Smart Recovery A: Remote GitHub repo already has an initial README/LICENSE commit (`fetch first` / `non-fast-forward`)
      if (lower.includes("fetch first") || lower.includes("non-fast-forward") || lower.includes("rejected")) {
        const recovery = await vscode.window.showWarningMessage(
          `Target GitHub repository already has commits not present locally (e.g. an initial README). How should VibeArmor push your folder?`,
          { modal: true },
          "Push as Safe PR Branch (Recommended)",
          "Pull Rebase & Push",
          "Force Overwrite Remote Branch"
        );
        try {
          if (recovery === "Push as Safe PR Branch (Recommended)") {
            const prBranch = `vibearmor/safe-push-${Math.floor(Date.now() / 1000)}`;
            await runGitAsync(repoDir, ["checkout", "-B", prBranch]);
            await runGitAsync(repoDir, ["push", "-u", "origin", prBranch]);
            renderWebview();
            const prUrl = webRepoUrl ? `${webRepoUrl}/compare/${encodeURIComponent(prBranch)}?expand=1` : "";
            const picked = await vscode.window.showInformationMessage(
              `✅ Pushed branch '${prBranch}' cleanly to GitHub!`,
              ...(prUrl ? ["Open Pull Request on GitHub ↗"] : [])
            );
            if (picked && prUrl) vscode.env.openExternal(vscode.Uri.parse(prUrl));
            return;
          }
          if (recovery === "Pull Rebase & Push") {
            const br = detectGitBranch(repoDir);
            await runGitAsync(repoDir, ["pull", "--rebase", "--allow-unrelated-histories", "origin", br]);
            await runGitAsync(repoDir, ["push", "-u", "origin", br]);
            renderWebview();
            vscode.window.showInformationMessage(`✅ Rebased and pushed '${br}' to GitHub!`);
            return;
          }
          if (recovery === "Force Overwrite Remote Branch") {
            const br = detectGitBranch(repoDir);
            await runGitAsync(repoDir, ["push", "-u", "--force", "origin", br]);
            renderWebview();
            vscode.window.showInformationMessage(`✅ Force-pushed verified folder to '${br}' on GitHub!`);
            return;
          }
        } catch (recErr: unknown) {
          vscode.window.showErrorMessage(
            `Git recovery failed: ${recErr instanceof Error ? recErr.message : String(recErr)}`
          );
          return;
        }
        return;
      }

      // Smart Recovery B: Interactive Credential Manager / Auth / Wrong Repo URL
      const action = await vscode.window.showErrorMessage(
        `Git push error: ${msg}`,
        "Run Push in VS Code Terminal (Sign In)",
        "Change GitHub Repo URL"
      );
      if (action === "Run Push in VS Code Terminal (Sign In)") {
        launchInteractiveTerminalPush(repoDir, detectGitBranch(repoDir));
      } else if (action === "Change GitHub Repo URL") {
        await ensureGitRemoteOrigin(repoDir, true);
      }
    }
  }

  async function pairWorkspaceFlow() {
    const folder = vscode.workspace.workspaceFolders?.[0];
    const current = getPairToken();
    const entered = await vscode.window.showInputBox({
      prompt: "Paste Pairing Token (va_pair_...) from VibeArmor Studio, or leave empty to auto-create one",
      value: current,
      placeHolder: "va_pair_xxxxxxxxxxxx",
    });
    if (entered === undefined) return;
    let token = entered.trim();
    if (!token) {
      try {
        const created = await httpJson<{ pair_token: string }>("POST", getServerUrl(), "/api/extension/pair/create", {
          editor: detectEditorName(),
          workspace_name: folder?.name || "editor-workspace",
        });
        token = created.pair_token;
      } catch (err: unknown) {
        vscode.window.showErrorMessage(`Could not create pairing token: ${err instanceof Error ? err.message : String(err)}`);
        return;
      }
    }
    await vscode.workspace.getConfiguration("vibearmor").update("pairToken", token, vscode.ConfigurationTarget.Workspace);
    await installGitPushGate();
    await syncAndVerify();
    vscode.window.showInformationMessage(`VibeArmor: Paired with Web Studio (${token})! Two-way live sync active.`);
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("vibearmor.verifyReadiness", () => syncAndVerify(false)),
    vscode.commands.registerCommand("vibearmor.pairWorkspace", pairWorkspaceFlow),
    vscode.commands.registerCommand("vibearmor.reviewSurgicalFixes", () => adoptSelectedSurgicalFixes()),
    vscode.commands.registerCommand("vibearmor.safePushToGitHub", () => safePushToGitHub(false)),
    vscode.commands.registerCommand("vibearmor.installPushHook", installGitPushGate),
    vscode.commands.registerCommand("vibearmor.configureGitRemote", configureGitRemoteFlow),
    vscode.commands.registerCommand("vibearmor.openInWebStudio", () => {
      const url = pairedProjectId
        ? `${getServerUrl().replace(/\/$/, "")}/?project=${encodeURIComponent(pairedProjectId)}&step=step1_graph`
        : getServerUrl();
      vscode.env.openExternal(vscode.Uri.parse(url));
    }),
    vscode.commands.registerCommand("vibearmor.connectServer", async () => {
      const next = await vscode.window.showInputBox({
        prompt: "Enter your VibeArmor Web Application URL",
        value: getServerUrl(),
      });
      if (next) {
        await vscode.workspace.getConfiguration("vibearmor").update("serverUrl", next.trim(), vscode.ConfigurationTarget.Global);
        await syncAndVerify();
      }
    }),
    vscode.window.registerWebviewViewProvider("vibearmor.readinessPanel", {
      resolveWebviewView(view) {
        webviewRef = view;
        view.webview.options = { enableScripts: true };
        view.webview.onDidReceiveMessage((msg) => {
          if (msg.cmd === "verify") syncAndVerify(false);
          if (msg.cmd === "pair") pairWorkspaceFlow();
          if (msg.cmd === "hook") installGitPushGate();
          if (msg.cmd === "safePush") safePushToGitHub(false);
          if (msg.cmd === "termPush") safePushToGitHub(true);
          if (msg.cmd === "cfgRemote") configureGitRemoteFlow();
          if (msg.cmd === "diff") openProposalSplitDiff(msg.id);
          if (msg.cmd === "adoptSelected") adoptSelectedSurgicalFixes(msg.ids);
          if (msg.cmd === "openWeb") vscode.commands.executeCommand("vibearmor.openInWebStudio");
          if (msg.cmd === "cfgServer") vscode.commands.executeCommand("vibearmor.connectServer");
        });
        renderWebview();
      },
    })
  );

  if (vscode.workspace.workspaceFolders?.length) {
    setTimeout(() => syncAndVerify(true), 600);
  }
}

export function deactivate() {}
