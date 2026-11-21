#!/usr/bin/env node
/**
 * VibeArmor Full-Stack Dev Launcher (Windows PowerShell / CMD · macOS · Linux)
 *
 * Automatically starts BOTH:
 *   1. Python FastAPI Security Engine on http://127.0.0.1:8000 (auto-detecting .venv & installing wheels if missing)
 *   2. Vite React Studio UI on http://localhost:5173 (proxying /api/* -> 127.0.0.1:8000)
 *
 * Eliminates `ECONNREFUSED 127.0.0.1:8000` when running `npm run dev` inside VS Code!
 */
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const studioDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(studioDir, "..");
const isWin = process.platform === "win32";

function checkBackendAlive() {
  return new Promise((resolve) => {
    const req = http.get("http://127.0.0.1:8000/api/policy", { timeout: 1200 }, (res) => {
      res.resume();
      resolve(res.statusCode && res.statusCode < 500);
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

function resolveWorkingPython() {
  const venvRel = isWin ? path.join("Scripts", "python.exe") : path.join("bin", "python");
  const candidates = [];
  if (process.env.VIRTUAL_ENV) {
    candidates.push(path.join(process.env.VIRTUAL_ENV, venvRel));
  }
  candidates.push(
    path.join(repoRoot, ".venv", venvRel),
    path.join(repoRoot, "venv", venvRel),
    path.join(path.resolve(repoRoot, ".."), ".venv", venvRel),
    ...(isWin ? ["python", "py", "python3"] : ["python3", "python"])
  );

  for (const cand of candidates) {
    try {
      if (cand.includes(path.sep) && !fs.existsSync(cand)) continue;
      const out = execFileSync(cand, ["-c", "import sys; print(sys.executable)"], {
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 5000,
      }).trim();
      if (out) return cand;
    } catch {
      // try next candidate
    }
  }
  return null;
}

function ensurePythonDependencies(pyBin) {
  const env = { ...process.env, PYTHONPATH: repoRoot };
  try {
    execFileSync(
      pyBin,
      ["-c", "import fastapi, uvicorn, pydantic, httpx, sqlglot, tree_sitter, yaml, faiss, langgraph"],
      { cwd: repoRoot, env, stdio: "ignore", timeout: 10000 }
    );
    return;
  } catch {
    console.log("\x1b[36m[VibeArmor] Installing Python backend requirements (one-time setup)...\x1b[0m");
    execFileSync(pyBin, ["-m", "pip", "install", "-r", path.join(repoRoot, "requirements.txt")], {
      cwd: repoRoot,
      env,
      stdio: "inherit",
    });
    execFileSync(pyBin, ["-m", "pip", "install", "-e", repoRoot, "--no-deps"], {
      cwd: repoRoot,
      env,
      stdio: "inherit",
    });
  }
}

function ensureFrontendDependencies() {
  const viteBin = path.join(studioDir, "node_modules", "vite", "bin", "vite.js");
  if (fs.existsSync(viteBin)) return viteBin;
  console.log("\x1b[36m[VibeArmor] Installing Studio frontend packages (one-time `npm install`)...\x1b[0m");
  execFileSync(isWin ? "npm.cmd" : "npm", ["install", "--no-audit", "--no-fund"], {
    cwd: studioDir,
    stdio: "inherit",
    shell: isWin,
  });
  return viteBin;
}

async function main() {
  const viteBin = ensureFrontendDependencies();
  let backendProc = null;
  const alreadyUp = await checkBackendAlive();

  if (alreadyUp) {
    console.log("\x1b[32m[VibeArmor] FastAPI backend already running on http://127.0.0.1:8000 ✓\x1b[0m");
  } else {
    const pyBin = resolveWorkingPython();
    if (!pyBin) {
      console.error(
        "\x1b[31m[VibeArmor] Python 3.10+ was not found on PATH. Install Python from https://python.org (check 'Add Python to PATH') and re-run `npm run dev`.\x1b[0m"
      );
      process.exit(1);
    }

    ensurePythonDependencies(pyBin);

    console.log(`\x1b[36m[VibeArmor] Starting FastAPI Security Backend on http://127.0.0.1:8000 (${pyBin})...\x1b[0m`);
    backendProc = spawn(
      pyBin,
      ["-m", "uvicorn", "core.interfaces.api:app", "--host", "127.0.0.1", "--port", "8000"],
      {
        cwd: repoRoot,
        env: { ...process.env, PYTHONPATH: repoRoot },
        stdio: "inherit",
      }
    );

    let ready = false;
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 300));
      if (await checkBackendAlive()) {
        ready = true;
        break;
      }
    }
    if (ready) {
      console.log("\x1b[32m[VibeArmor] Backend Engine LIVE on http://127.0.0.1:8000 ✓\x1b[0m");
    } else {
      console.warn("\x1b[33m[VibeArmor] Backend still warming up on :8000 — starting Vite UI...\x1b[0m");
    }
  }

  const extraArgs = process.argv.slice(2);
  const viteProc = spawn(
    process.execPath,
    [viteBin, "--host", "0.0.0.0", "--port", "5173", ...extraArgs],
    {
      cwd: studioDir,
      stdio: "inherit",
    }
  );

  const cleanup = () => {
    try {
      if (viteProc && !viteProc.killed) viteProc.kill();
    } catch {}
    try {
      if (backendProc && !backendProc.killed) backendProc.kill();
    } catch {}
  };

  process.on("SIGINT", () => {
    cleanup();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    cleanup();
    process.exit(0);
  });
  process.on("exit", cleanup);

  viteProc.on("exit", (code) => {
    cleanup();
    process.exit(code ?? 0);
  });
}

main().catch((err) => {
  console.error("[VibeArmor] Dev launcher error:", err);
  process.exit(1);
});
