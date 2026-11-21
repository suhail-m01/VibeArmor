import React, { useMemo, useState } from "react";
import {
  Shield,
  Mail,
  Lock,
  User,
  Building2,
  Eye,
  EyeOff,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  Layers,
  Cpu,
  AlertCircle,
} from "lucide-react";

export interface AuthUserProfile {
  name: string;
  email: string;
  organization: string;
  role: string;
  createdAt: string;
}

interface StoredAccount extends AuthUserProfile {
  passwordHash: string;
}

const USERS_STORAGE_KEY = "vibearmor_accounts_v1";
export const ACTIVE_SESSION_STORAGE_KEY = "vibearmor_active_session_v1";

function simpleHash(raw: string): string {
  let h = 2166136261;
  for (let i = 0; i < raw.length; i++) {
    h ^= raw.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}

function readStoredAccounts(): StoredAccount[] {
  try {
    const raw = localStorage.getItem(USERS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveStoredAccounts(accounts: StoredAccount[]): void {
  try {
    localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(accounts));
  } catch {
    // ignore quota errors
  }
}

export function loadActiveUserSession(): AuthUserProfile | null {
  try {
    const raw = localStorage.getItem(ACTIVE_SESSION_STORAGE_KEY) || sessionStorage.getItem(ACTIVE_SESSION_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as AuthUserProfile;
  } catch {
    return null;
  }
}

export function persistActiveUserSession(profile: AuthUserProfile, remember = true): void {
  try {
    const str = JSON.stringify(profile);
    sessionStorage.setItem(ACTIVE_SESSION_STORAGE_KEY, str);
    if (remember) {
      localStorage.setItem(ACTIVE_SESSION_STORAGE_KEY, str);
    }
  } catch {
    // ignore storage errors
  }
}

export function clearActiveUserSession(): void {
  try {
    localStorage.removeItem(ACTIVE_SESSION_STORAGE_KEY);
    sessionStorage.removeItem(ACTIVE_SESSION_STORAGE_KEY);
  } catch {
    // ignore storage errors
  }
}

interface Props {
  initialMode?: "login" | "signup";
  onAuthenticated: (user: AuthUserProfile) => void;
}

export const AuthGatewayView: React.FC<Props> = ({ initialMode = "login", onAuthenticated }) => {
  const [mode, setMode] = useState<"login" | "signup">(initialMode);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [organization, setOrganization] = useState("Presidency University · NeXGen Coders");
  const [role, setRole] = useState("DevSecOps Lead");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const passwordStrength = useMemo(() => {
    if (!password) return { score: 0, label: "Enter password", color: "bg-slate-200" };
    let s = 0;
    if (password.length >= 6) s++;
    if (password.length >= 10) s++;
    if (/[A-Z]/.test(password) && /[0-9]/.test(password)) s++;
    if (/[^A-Za-z0-9]/.test(password)) s++;
    if (s <= 1) return { score: 1, label: "Fair", color: "bg-amber-400" };
    if (s === 2) return { score: 2, label: "Good", color: "bg-sky-500" };
    if (s === 3) return { score: 3, label: "Strong", color: "bg-indigo-600" };
    return { score: 4, label: "Very Strong", color: "bg-emerald-500" };
  }, [password]);

  function switchMode(next: "login" | "signup") {
    setError(null);
    setMode(next);
  }

  function handleInstantDemoAccess() {
    const demoProfile: AuthUserProfile = {
      name: "Suhail M",
      email: "suhail@vibearmor.security",
      organization: "NeXGen Coders · Presidency University",
      role: "Principal Security Architect",
      createdAt: new Date().toISOString(),
    };
    persistActiveUserSession(demoProfile, true);
    onAuthenticated(demoProfile);
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !cleanEmail.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }
    if (password.length < 4) {
      setError("Password must be at least 4 characters.");
      return;
    }

    setSubmitting(true);
    setTimeout(() => {
      const accounts = readStoredAccounts();

      if (mode === "signup") {
        const cleanName = name.trim();
        if (!cleanName) {
          setSubmitting(false);
          setError("Please enter your full name.");
          return;
        }
        if (confirmPassword && password !== confirmPassword) {
          setSubmitting(false);
          setError("Passwords do not match.");
          return;
        }
        const existsIdx = accounts.findIndex((a) => a.email === cleanEmail);
        const newAccount: StoredAccount = {
          name: cleanName,
          email: cleanEmail,
          organization: organization.trim() || "Security Workspace",
          role,
          createdAt: new Date().toISOString(),
          passwordHash: simpleHash(password),
        };
        if (existsIdx >= 0) {
          accounts[existsIdx] = newAccount;
        } else {
          accounts.push(newAccount);
        }
        saveStoredAccounts(accounts);
        const { passwordHash: _unused, ...profile } = newAccount;
        persistActiveUserSession(profile, rememberMe);
        setSubmitting(false);
        onAuthenticated(profile);
        return;
      }

      const matched = accounts.find((a) => a.email === cleanEmail);
      if (matched) {
        if (matched.passwordHash !== simpleHash(password)) {
          setSubmitting(false);
          setError("Incorrect password. Please try again.");
          return;
        }
        const { passwordHash: _unused, ...profile } = matched;
        persistActiveUserSession(profile, rememberMe);
        setSubmitting(false);
        onAuthenticated(profile);
        return;
      }

      const inferredName = cleanEmail
        .split("@")[0]
        .replace(/[._-]+/g, " ")
        .replace(/\b\w/g, (c) => c.toUpperCase());
      const autoAccount: StoredAccount = {
        name: inferredName || "Security Lead",
        email: cleanEmail,
        organization: "Presidency University · NeXGen Coders",
        role: "Security Architect",
        createdAt: new Date().toISOString(),
        passwordHash: simpleHash(password),
      };
      accounts.push(autoAccount);
      saveStoredAccounts(accounts);
      const { passwordHash: _unused2, ...profile } = autoAccount;
      persistActiveUserSession(profile, rememberMe);
      setSubmitting(false);
      onAuthenticated(profile);
    }, 220);
  }

  return (
    <div className="min-h-screen relative overflow-hidden flex flex-col justify-between bg-[#F8FAFC] text-[#0F172A]">
      {/* Drifting Luxury Ambient Light Orbs */}
      <div className="pointer-events-none absolute -top-28 -left-20 h-[440px] w-[440px] rounded-full bg-indigo-200/40 blur-3xl animate-lux-aurora" />
      <div
        className="pointer-events-none absolute top-20 -right-24 h-[400px] w-[400px] rounded-full bg-sky-200/35 blur-3xl animate-lux-aurora"
        style={{ animationDelay: "-5s" }}
      />
      <div
        className="pointer-events-none absolute -bottom-32 left-1/3 h-[380px] w-[380px] rounded-full bg-emerald-200/30 blur-3xl animate-lux-aurora"
        style={{ animationDelay: "-10s" }}
      />

      {/* Minimalist Top Bar */}
      <header className="relative z-10 w-full max-w-7xl mx-auto px-6 pt-6 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-600 to-violet-600 text-white shadow-md shadow-indigo-500/25">
            <Shield className="h-5 w-5 stroke-[2.2]" />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-lg font-extrabold tracking-tight text-slate-900">VibeArmor</span>
            <span className="rounded-full bg-indigo-50 border border-indigo-200/80 px-2 py-0.5 font-mono text-[10px] font-bold text-indigo-700">
              v3.6
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => switchMode(mode === "login" ? "signup" : "login")}
            className="rounded-full border border-slate-200 bg-white/90 px-4 py-2 text-xs font-bold text-slate-700 shadow-sm hover:border-indigo-300 hover:text-indigo-700 cursor-pointer"
          >
            {mode === "login" ? "Create Account" : "Sign In"}
          </button>
          <button
            type="button"
            onClick={handleInstantDemoAccess}
            className="lux-btn-shimmer inline-flex items-center gap-1.5 rounded-full bg-slate-900 px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-indigo-700 cursor-pointer"
          >
            <Sparkles className="h-3.5 w-3.5 text-indigo-300" />
            1-Click Demo
          </button>
        </div>
      </header>

      {/* Main Split Showcase */}
      <main className="relative z-10 flex-1 flex items-center justify-center px-6 py-8">
        <div className="w-full max-w-6xl grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          {/* Left: Minimalist Headline + Animated Security Orbit Showcase */}
          <div className="lg:col-span-6 space-y-7 animate-lux-fade-up">
            <div className="space-y-3.5">
              <div className="inline-flex items-center gap-2 rounded-full border border-indigo-200/80 bg-white/90 px-3.5 py-1.5 text-[11px] font-bold text-indigo-700 shadow-sm">
                <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                Autonomous DevSecOps Guard
              </div>

              <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-slate-950 leading-[1.1]">
                Code Fearlessly.
                <br />
                <span className="lux-gradient-text">Ship Verified.</span>
              </h1>

              <p className="text-sm text-slate-500 max-w-md leading-relaxed">
                Surgical AST &amp; RAG verification before every Git push.
              </p>
            </div>

            {/* Animated Interactive Orbital Security Core */}
            <div className="relative h-64 sm:h-72 w-full max-w-md flex items-center justify-center select-none">
              {/* Outer Rotating Ring */}
              <div className="absolute h-60 w-60 rounded-full border border-dashed border-indigo-300/70 animate-lux-orbit">
                <span className="absolute -top-1.5 left-1/2 -translate-x-1/2 h-3 w-3 rounded-full bg-indigo-500 shadow-sm shadow-indigo-500/50" />
                <span className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 h-2.5 w-2.5 rounded-full bg-sky-400" />
              </div>

              {/* Inner Reverse Rotating Ring */}
              <div className="absolute h-40 w-40 rounded-full border border-violet-200/90 animate-lux-orbit-reverse">
                <span className="absolute top-1/2 -right-1.5 -translate-y-1/2 h-2.5 w-2.5 rounded-full bg-emerald-500" />
              </div>

              {/* Expanding Pulse Halo */}
              <div className="absolute h-24 w-24 rounded-full bg-indigo-400/20 animate-lux-pulse-ring" />

              {/* Central Shield Core */}
              <div className="relative z-10 flex h-20 w-20 items-center justify-center rounded-3xl bg-gradient-to-br from-indigo-600 via-violet-600 to-indigo-700 text-white shadow-xl shadow-indigo-500/30 animate-lux-float">
                <Shield className="h-9 w-9 stroke-[2]" />
              </div>

              {/* Floating Pill 1 — Top Left */}
              <div className="absolute top-3 left-2 sm:left-4 rounded-2xl border border-slate-200/90 bg-white/95 backdrop-blur-md px-3.5 py-2 shadow-md flex items-center gap-2.5 animate-lux-float">
                <div className="flex h-7 w-7 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600">
                  <Cpu className="h-3.5 w-3.5" />
                </div>
                <div>
                  <div className="text-[11px] font-extrabold text-slate-900">AST + FAISS</div>
                  <div className="text-[9.5px] font-medium text-slate-400">Cross-Layer Graph</div>
                </div>
              </div>

              {/* Floating Pill 2 — Top Right */}
              <div
                className="absolute top-6 right-1 sm:right-3 rounded-2xl border border-emerald-200/90 bg-white/95 backdrop-blur-md px-3.5 py-2 shadow-md flex items-center gap-2 animate-lux-float-alt"
                style={{ animationDelay: "-1.8s" }}
              >
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                <div>
                  <div className="text-[11px] font-extrabold text-slate-900">3-Gate Proof</div>
                  <div className="text-[9.5px] font-medium text-emerald-600">Deterministic</div>
                </div>
              </div>

              {/* Floating Pill 3 — Bottom */}
              <div
                className="absolute bottom-3 left-8 sm:left-12 rounded-2xl border border-slate-200/90 bg-white/95 backdrop-blur-md px-3.5 py-2 shadow-md flex items-center gap-2.5 animate-lux-float"
                style={{ animationDelay: "-3.2s" }}
              >
                <div className="flex h-7 w-7 items-center justify-center rounded-xl bg-violet-50 text-violet-600">
                  <Layers className="h-3.5 w-3.5" />
                </div>
                <div>
                  <div className="text-[11px] font-extrabold text-slate-900">99.4% Untouched</div>
                  <div className="text-[9.5px] font-medium text-slate-400">Surgical Patching</div>
                </div>
              </div>
            </div>

            {/* Compact Ecosystem Tagline */}
            <div className="inline-flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-400">
              <span className="rounded-lg bg-white border border-slate-200/80 px-2.5 py-1 text-slate-600 shadow-sm">
                VS Code &amp; Cursor
              </span>
              <span className="rounded-lg bg-white border border-slate-200/80 px-2.5 py-1 text-slate-600 shadow-sm">
                Chrome MV3
              </span>
              <span className="rounded-lg bg-white border border-slate-200/80 px-2.5 py-1 text-slate-600 shadow-sm">
                GitHub PR Guard
              </span>
            </div>
          </div>

          {/* Right: Clean Porcelain Auth Card */}
          <div className="lg:col-span-6 flex justify-center lg:justify-end">
            <div
              key={mode}
              className="w-full max-w-md rounded-3xl border border-slate-200/90 bg-white/95 backdrop-blur-xl p-7 sm:p-8 shadow-[0_24px_64px_-16px_rgba(15,23,42,0.09)] animate-lux-scale-in"
            >
              {/* Segmented Pill Switcher */}
              <div className="grid grid-cols-2 rounded-2xl bg-slate-100/90 p-1 mb-6 border border-slate-200/60">
                <button
                  type="button"
                  onClick={() => switchMode("login")}
                  className={`rounded-xl py-2 text-xs font-extrabold transition-all cursor-pointer ${
                    mode === "login"
                      ? "bg-white text-slate-900 shadow-sm ring-1 ring-slate-200/80"
                      : "text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Sign In
                </button>
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  className={`rounded-xl py-2 text-xs font-extrabold transition-all cursor-pointer ${
                    mode === "signup"
                      ? "bg-white text-slate-900 shadow-sm ring-1 ring-slate-200/80"
                      : "text-slate-500 hover:text-slate-800"
                  }`}
                >
                  Create Account
                </button>
              </div>

              <div className="mb-5">
                <h2 className="text-xl font-extrabold tracking-tight text-slate-900">
                  {mode === "login" ? "Welcome back" : "Create your account"}
                </h2>
                <p className="mt-0.5 text-xs text-slate-500">
                  {mode === "login" ? "Enter your security workspace." : "Local-first profile · zero cloud sharing."}
                </p>
              </div>

              {error && (
                <div className="mb-4 flex items-start gap-2 rounded-xl border border-rose-200 bg-rose-50/90 px-3.5 py-2.5 text-xs font-medium text-rose-800 animate-lux-fade-up">
                  <AlertCircle className="h-4 w-4 text-rose-600 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-3.5">
                {mode === "signup" && (
                  <div className="space-y-3.5 animate-lux-fade-up">
                    <div>
                      <label className="block text-[11px] font-bold text-slate-700 mb-1">Full Name</label>
                      <div className="relative">
                        <User className="h-4 w-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                        <input
                          type="text"
                          value={name}
                          onChange={(e) => setName(e.target.value)}
                          placeholder="e.g. Suhail M"
                          className="w-full rounded-xl border border-slate-200 bg-slate-50/60 pl-10 pr-3.5 py-2.5 text-xs font-medium text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition"
                        />
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-[11px] font-bold text-slate-700 mb-1">Team</label>
                        <div className="relative">
                          <Building2 className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="text"
                            value={organization}
                            onChange={(e) => setOrganization(e.target.value)}
                            placeholder="Team / Org"
                            className="w-full rounded-xl border border-slate-200 bg-slate-50/60 pl-9 pr-3 py-2.5 text-xs font-medium text-slate-900 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition"
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-[11px] font-bold text-slate-700 mb-1">Role</label>
                        <select
                          value={role}
                          onChange={(e) => setRole(e.target.value)}
                          className="w-full rounded-xl border border-slate-200 bg-slate-50/60 px-3 py-2.5 text-xs font-semibold text-slate-800 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition"
                        >
                          <option value="DevSecOps Lead">DevSecOps Lead</option>
                          <option value="Full-Stack Engineer">Full-Stack Engineer</option>
                          <option value="Security Architect">Security Architect</option>
                          <option value="AI Researcher">AI Researcher</option>
                        </select>
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <label className="block text-[11px] font-bold text-slate-700 mb-1">Email</label>
                  <div className="relative">
                    <Mail className="h-4 w-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@university.edu"
                      className="w-full rounded-xl border border-slate-200 bg-slate-50/60 pl-10 pr-3.5 py-2.5 text-xs font-medium text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition"
                    />
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="block text-[11px] font-bold text-slate-700">Password</label>
                    {mode === "signup" && password && (
                      <span className="text-[10px] font-bold text-slate-500">{passwordStrength.label}</span>
                    )}
                  </div>
                  <div className="relative">
                    <Lock className="h-4 w-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type={showPass ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={mode === "login" ? "Enter your password" : "Create a strong password"}
                      className="w-full rounded-xl border border-slate-200 bg-slate-50/60 pl-10 pr-10 py-2.5 text-xs font-medium text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPass((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-700 cursor-pointer"
                      aria-label="Toggle password visibility"
                    >
                      {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>

                  {mode === "signup" && (
                    <div className="mt-2 grid grid-cols-4 gap-1.5">
                      {[1, 2, 3, 4].map((lvl) => (
                        <div
                          key={lvl}
                          className={`h-1 rounded-full transition-all duration-300 ${
                            passwordStrength.score >= lvl ? passwordStrength.color : "bg-slate-200"
                          }`}
                        />
                      ))}
                    </div>
                  )}
                </div>

                {mode === "signup" && (
                  <div className="animate-lux-fade-up">
                    <label className="block text-[11px] font-bold text-slate-700 mb-1">Confirm Password</label>
                    <div className="relative">
                      <Lock className="h-4 w-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                      <input
                        type={showPass ? "text" : "password"}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Re-enter password"
                        className="w-full rounded-xl border border-slate-200 bg-slate-50/60 pl-10 pr-3.5 py-2.5 text-xs font-medium text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition"
                      />
                    </div>
                  </div>
                )}

                <label className="inline-flex items-center gap-2 cursor-pointer text-xs text-slate-600 pt-0.5">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="h-3.5 w-3.5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  Remember me
                </label>

                <button
                  type="submit"
                  disabled={submitting}
                  className="lux-btn-shimmer w-full inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 px-5 py-3 text-xs font-extrabold text-white shadow-md shadow-indigo-500/20 hover:from-indigo-700 hover:to-violet-700 disabled:opacity-60 cursor-pointer"
                >
                  {submitting
                    ? "Signing in..."
                    : mode === "login"
                    ? "Sign In"
                    : "Create Account"}
                  <ArrowRight className="h-4 w-4" />
                </button>
              </form>

              <div className="relative my-4">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-200/80" />
                </div>
                <div className="relative flex justify-center text-[10px] font-bold uppercase tracking-wider">
                  <span className="bg-white px-3 text-slate-400">Or</span>
                </div>
              </div>

              <button
                type="button"
                onClick={handleInstantDemoAccess}
                className="w-full inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-2.5 text-xs font-bold text-slate-800 hover:border-indigo-300 hover:bg-indigo-50/50 hover:text-indigo-800 cursor-pointer"
              >
                <Sparkles className="h-3.5 w-3.5 text-indigo-600" />
                Instant Demo Dashboard
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* Clean Minimal Footer */}
      <footer className="relative z-10 w-full max-w-7xl mx-auto px-6 py-4 flex items-center justify-between text-[11px] text-slate-400">
        <span>VibeArmor v3.6 · Team NeXGen Coder&apos;s</span>
        <span>Local-First Security</span>
      </footer>
    </div>
  );
};
