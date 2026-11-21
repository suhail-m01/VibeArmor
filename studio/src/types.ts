export interface SecurityNode {
  id: string;
  kind: "frontend_component" | "api_route" | "sql_table" | "sql_function" | "dependency" | "secret_token";
  label: string;
  file_path: string;
  line: number;
  status: "safe" | "vulnerable" | "healed" | "abstained";
  metadata: Record<string, unknown>;
}

export interface SecurityEdge {
  source: string;
  target: string;
  relation: string;
  risk: "safe" | "critical" | "high" | "healed";
  detail: string;
}

export interface Finding {
  id: string;
  pillar: "rls_dpdp" | "secret_boundary" | "taint_payment" | "supply_chain";
  rule_id: string;
  cwe: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  description: string;
  blast_radius: string;
  file_path: string;
  line_start: number;
  line_end: number;
  snippet: string;
  linked_files: string[];
  dpdp_pii_columns: string[];
  reachable: boolean;
  requires_policy_spec: boolean;
  abstention_reason?: string | null;
  metadata: Record<string, unknown>;
}

export interface MinimalSecuritySlice {
  finding_id: string;
  file_path: string;
  full_file_lines: number;
  slice_lines: number;
  full_file_tokens_est: number;
  slice_tokens_est: number;
  compression_pct: number;
  primary_slice: string;
  cross_layer_context: string;
  repair_strategy: string;
}

export interface FileEdit {
  file_path: string;
  before_content: string;
  after_content: string;
  unified_diff: string;
  created_new: boolean;
}

export interface GateCheck {
  gate_name: string;
  passed: boolean;
  latency_ms: number;
  summary: string;
  details: string[];
}

export interface PatchReport {
  finding_id: string;
  rule_id: string;
  pillar: string;
  status: "FIXED_VERIFIED" | "ABSTAINED" | "INFO_ONLY" | "ROLLBACK_ON_GATE_FAIL" | "UNPATCHED";
  strategy_used: string;
  slm_backend?: string | null;
  mss?: MinimalSecuritySlice | null;
  edits: FileEdit[];
  gates: GateCheck[];
  abstention_note?: string | null;
  repair_latency_ms: number;
}

export interface ScanAndHealReport {
  workspace: string;
  mode: string;
  clean_fast_path: boolean;
  scan_latency_ms: number;
  total_latency_ms: number;
  llm_calls_made: number;
  nodes: SecurityNode[];
  edges: SecurityEdge[];
  findings_before: Finding[];
  findings_after: Finding[];
  patches: PatchReport[];
  abstentions: Finding[];
  summary: {
    total_findings_before: number;
    actionable_before: number;
    actionable_after: number;
    verified_fixed_count: number;
    abstained_policy_count: number;
    unreachable_info_filtered: number;
    broken_builds: number;
    avg_mss_token_compression_pct: number;
    scan_latency_ms: number;
    total_latency_ms: number;
    llm_calls_made: number;
  };
}

export interface ProjectSummary {
  id: string;
  name: string;
  source_type: "github" | "zip" | "reference" | "editor-paired";
  source_label: string;
  security_score: number;
  mode: string;
  actionable_open: number;
  verified_fixed: number;
  abstained: number;
  scan_latency_ms: number;
  node_count: number;
}

export interface ProjectMetaDetail {
  id: string;
  name: string;
  source_type: "github" | "zip" | "reference" | "editor-paired";
  source_label: string;
  github_repo_url?: string | null;
  github_branch?: string | null;
  adopted?: boolean;
  security_score: number;
  digest: string;
}

export interface BreachAttack {
  id: string;
  title: string;
  command: string;
  blocked: boolean;
  http_status: number;
  active_sql_policy?: string;
  dpdp_exposure?: string;
  leaked_rows?: Array<Record<string, string | number>>;
  legitimate_user_check?: string;
  extracted_secret?: string | null;
  bff_guards?: Record<string, boolean>;
  bff_probe?: string;
  sqli_payload_used?: string;
  sqli_rows_dumped?: number;
  sqli_leaked_data?: Array<Record<string, string | number>>;
  sqli_error?: string | null;
  razorpay_response?: Record<string, unknown>;
  razorpay_zero_rupee_status?: string;
  legitimate_checkout_check?: string;
  current_dependencies?: Record<string, string>;
  slopsquat_status?: string;
  cve_status?: string;
}

export interface BreachSimulation {
  latency_ms: number;
  all_blocked: boolean;
  blocked_count: number;
  total_attacks: number;
  attacks: BreachAttack[];
}

export interface ProjectDetailPayload {
  project: ProjectMetaDetail;
  report: ScanAndHealReport;
  files: Record<string, string>;
  before_files: Record<string, string>;
  breach: BreachSimulation | null;
}

export interface StreamEventItem {
  stage: string;
  message: string;
  elapsed_ms: number;
  rule_id?: string;
  file_path?: string;
}

export interface ComparisonRow {
  system: string;
  securityeval_recall_pct: number;
  vibestack_recall_pct: number;
  overall_verified_autofix_pct: number;
  false_positive_rate_pct: number;
  broken_builds_pct: number;
  median_latency_ms: number;
}

export interface AblationRow {
  file_lines: number;
  full_file_tokens: number;
  mss_slice_lines: number;
  mss_slice_tokens: number;
  token_reduction_pct: number;
}

export interface FailureCase {
  id: string;
  boundary_type: string;
  expected: string;
  abstained_safely: boolean;
  reason: string;
}

export interface EvalResults {
  benchmark_version: string;
  hypothesis: string;
  datasets: {
    securityeval_30_count: number;
    vibestack_vulnerable_count: number;
    vibestack_hard_negatives_count: number;
    failure_modes_count: number;
    total_evaluated_cases: number;
  };
  comparison_table: ComparisonRow[];
  context_scaling_ablation: AblationRow[];
  failure_modes_6: {
    total_boundary_cases: number;
    safe_abstentions: number;
    safe_abstention_rate_pct: number;
    unsafe_hallucinated_patches: number;
    cases: FailureCase[];
  };
}

export interface SupabaseAuditedTable {
  table: string;
  columns: string[];
  dpdp_pii_columns: string[];
  owner_column: string | null;
  anon_endpoint_open: boolean;
  anon_rows_visible: number;
  risk: "CRITICAL" | "HIGH" | "MEDIUM" | "SAFE";
}

export interface SupabaseAuditResult {
  supabase_url: string;
  latency_ms: number;
  tables_discovered: number;
  tables: SupabaseAuditedTable[];
  recommended_rls_migration: string;
}

export interface PrecisionMetrics {
  created_new: boolean;
  original_lines: number;
  untouched_lines: number;
  changed_lines_before: number;
  added_lines_after: number;
  preservation_pct: number;
  changed_span_label: string;
  vulnerable_excerpt: string;
  corrected_excerpt: string;
}

export interface StagedFileDiff {
  file_path: string;
  created_new: boolean;
  before_content: string;
  after_content: string;
  unified_diff: string;
  precision: PrecisionMetrics;
}

export interface StagedProposalItem {
  finding_id: string;
  rule_id: string;
  pillar: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cwe: string;
  title: string;
  description: string;
  file_path: string;
  line_start: number;
  line_end: number;
  status: string;
  adoptable: boolean;
  abstention_note?: string | null;
  strategy_used: string;
  repair_latency_ms?: number;
  mss?: MinimalSecuritySlice | null;
  gates: GateCheck[];
  file_diffs: StagedFileDiff[];
  precision: PrecisionMetrics | null;
}

export interface StagedProposalBundle {
  project_id: string;
  adoptable_count: number;
  untouched_safe_files: string[];
  touched_vulnerable_files: string[];
  avg_non_vulnerable_preservation_pct: number;
  proposals: StagedProposalItem[];
  staged_files: Record<string, string>;
  original_files: Record<string, string>;
}

export interface GitHubPushResult {
  mode: "pull_request" | "direct_commit";
  repo: string;
  branch: string;
  base_branch?: string;
  commit_sha: string;
  commit_url?: string;
  pr_number?: number | null;
  pr_url?: string;
  compare_only?: boolean;
  note?: string;
  files_pushed: string[];
  secret_files_excluded: string[];
}

export interface ExtensionEventRecord {
  session_id: string;
  timestamp: string;
  editor: string;
  workspace_name: string;
  branch: string;
  ready_to_push: boolean;
  ready_to_deploy: boolean;
  blocking_count: number;
  security_score: number;
}

export interface PairingSessionRecord {
  pair_token: string;
  editor: string;
  workspace_name: string;
  local_path: string;
  branch: string;
  project_id?: string | null;
  connected: boolean;
  ready_to_push: boolean;
  security_score: number;
  open_threats: number;
  pending_fixes_count: number;
  pending_file_names: string[];
  synced_fixes_total: number;
  last_event: string;
  seconds_since_activity: number;
}

export interface BrowserCheckResult {
  audited: boolean;
  project_id?: string | null;
  repo_slug: string;
  ready_to_push: boolean;
  gate_verdict?: "READY" | "BLOCKED";
  security_score: number;
  open_threats: number;
  checks: Record<string, { passed: boolean; count: number; label: string }>;
  top_findings: Array<{
    rule_id: string;
    severity: string;
    title: string;
    file_path: string;
    line_start: number;
  }>;
}

export interface ExtensionStatusPayload {
  extension_name: string;
  version: string;
  vsix_ready: boolean;
  vsix_size_bytes: number;
  download_url: string;
  browser_ext_ready?: boolean;
  browser_ext_size_bytes?: number;
  browser_download_url?: string;
  bridge_ready?: boolean;
  bridge_download_url?: string;
  paired_sessions?: PairingSessionRecord[];
  supported_editors: Array<{ id: string; name: string; install_cmd: string }>;
  recent_verifications: ExtensionEventRecord[];
}

export interface ExtensionVerifyResult extends ExtensionEventRecord {
  project_id?: string | null;
  node_count?: number;
  edge_count?: number;
  checks: Record<string, { passed: boolean; count: number; label: string }>;
  scan_latency_ms: number;
  findings: Finding[];
  proposals: StagedProposalItem[];
}
