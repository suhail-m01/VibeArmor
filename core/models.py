"""Core data models for VibeArmor Cross-Layer Graph, Findings, MSS, Patches, and Verification Gates."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Pillar(str, Enum):
    RLS_DPDP = "rls_dpdp"
    SECRET_BOUNDARY = "secret_boundary"
    TAINT_PAYMENT = "taint_payment"
    SUPPLY_CHAIN = "supply_chain"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RemediationStatus(str, Enum):
    FIXED_VERIFIED = "FIXED_VERIFIED"
    ABSTAINED = "ABSTAINED"
    INFO_ONLY = "INFO_ONLY"
    ROLLBACK_ON_GATE_FAIL = "ROLLBACK_ON_GATE_FAIL"
    UNPATCHED = "UNPATCHED"


class NodeKind(str, Enum):
    FRONTEND_COMPONENT = "frontend_component"
    API_ROUTE = "api_route"
    SQL_TABLE = "sql_table"
    SQL_FUNCTION = "sql_function"
    DEPENDENCY = "dependency"
    SECRET_TOKEN = "secret_token"


class SecurityNode(BaseModel):
    id: str
    kind: NodeKind
    label: str
    file_path: str
    line: int = 1
    status: str = "safe"  # "safe" | "vulnerable" | "healed" | "abstained"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityEdge(BaseModel):
    source: str
    target: str
    relation: str  # e.g. "queries_anon", "exposes_secret", "taint_flow", "imports_pkg", "cloud_drift"
    risk: str = "safe"  # "safe" | "critical" | "high" | "healed"
    detail: str = ""


class Finding(BaseModel):
    id: str
    pillar: Pillar
    rule_id: str
    cwe: str
    severity: Severity
    title: str
    description: str
    blast_radius: str
    file_path: str
    line_start: int = 1
    line_end: int = 1
    snippet: str = ""
    linked_files: List[str] = Field(default_factory=list)
    dpdp_pii_columns: List[str] = Field(default_factory=list)
    reachable: bool = True
    requires_policy_spec: bool = False
    abstention_reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MinimalSecuritySlice(BaseModel):
    finding_id: str
    file_path: str
    full_file_lines: int
    slice_lines: int
    full_file_tokens_est: int
    slice_tokens_est: int
    compression_pct: float
    primary_slice: str
    cross_layer_context: str = ""
    repair_strategy: str = "deterministic"  # "deterministic" | "slm_mss" | "abstain"


class FileEdit(BaseModel):
    file_path: str
    before_content: str
    after_content: str
    unified_diff: str
    created_new: bool = False


class GateCheck(BaseModel):
    gate_name: str
    passed: bool
    latency_ms: float
    summary: str
    details: List[str] = Field(default_factory=list)


class PatchReport(BaseModel):
    finding_id: str
    rule_id: str
    pillar: Pillar
    status: RemediationStatus
    strategy_used: str  # "deterministic_codemod" | "slm_qwen_mss" | "abstain_policy_spec"
    slm_backend: Optional[str] = None
    mss: Optional[MinimalSecuritySlice] = None
    edits: List[FileEdit] = Field(default_factory=list)
    gates: List[GateCheck] = Field(default_factory=list)
    abstention_note: Optional[str] = None
    repair_latency_ms: float = 0.0


class ScanAndHealReport(BaseModel):
    workspace: str
    mode: str  # "scan_only" | "auto_heal"
    clean_fast_path: bool
    scan_latency_ms: float
    total_latency_ms: float
    llm_calls_made: int = 0
    nodes: List[SecurityNode] = Field(default_factory=list)
    edges: List[SecurityEdge] = Field(default_factory=list)
    findings_before: List[Finding] = Field(default_factory=list)
    findings_after: List[Finding] = Field(default_factory=list)
    patches: List[PatchReport] = Field(default_factory=list)
    abstentions: List[Finding] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
