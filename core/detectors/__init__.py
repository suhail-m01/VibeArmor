"""Four-pillar cross-layer vulnerability and supply-chain detectors."""

from __future__ import annotations

from typing import List

from core.detectors.rls_dpdp import detect_rls_and_access
from core.detectors.secret_boundary import detect_secrets_and_boundaries
from core.detectors.supply_chain import detect_supply_chain
from core.detectors.taint_payment import detect_taint_and_payments
from core.graph.cross_layer_graph import WorkspaceContext
from core.models import Finding


def run_all_detectors(ctx: WorkspaceContext, check_live_registry: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    rls_findings = detect_rls_and_access(ctx)
    findings.extend(rls_findings)
    findings.extend(detect_secrets_and_boundaries(ctx, rls_findings))
    findings.extend(detect_taint_and_payments(ctx))
    findings.extend(detect_supply_chain(ctx, check_live_registry=check_live_registry))
    return findings
