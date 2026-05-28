"""Render a TriageResult as an ops-ready text report."""

from __future__ import annotations

from .guardrails import GuardDecision
from .pipeline import TriageResult

_VERDICT_LABEL = {
    "allow_auto": "AUTO",
    "needs_approval": "APPROVE",
    "denied": "DENIED",
}


def _decision_line(d: GuardDecision) -> str:
    label = _VERDICT_LABEL[d.verdict]
    return (
        f"  [{label}] {d.action.op} -> {d.action.target} "
        f"({d.action.kind}): {d.reason}"
    )


def render_report(result: TriageResult) -> str:
    lines: list[str] = []
    lines.append("ALERTWARD TRIAGE REPORT")
    lines.append("=" * 60)
    lines.append(
        f"Incidents: {len(result.incidents)} | "
        f"auto-executed: {len(result.executed)} | "
        f"awaiting approval: {len(result.pending_approval)} | "
        f"denied: {len(result.denied)}"
    )
    lines.append("")

    by_incident = {d.action.args.get("incident_id"): d for d in result.decisions}
    for inc in result.incidents:
        lines.append(f"{inc.incident_id}  [{inc.severity.upper()}] {inc.service}")
        lines.append(f"  category: {inc.category} | alerts: {', '.join(inc.alert_ids)}")
        lines.append(f"  {inc.summary}")
        decision = by_incident.get(inc.incident_id)
        if decision is not None:
            lines.append(_decision_line(decision))
        lines.append("")

    if result.pending_approval:
        lines.append("AWAITING HUMAN APPROVAL")
        lines.append("-" * 60)
        for action in result.pending_approval:
            lines.append(f"  {action.op} -> {action.target}: {action.rationale}")
        lines.append("")

    if result.denied:
        lines.append("DENIED BY POLICY (never auto-run)")
        lines.append("-" * 60)
        for action in result.denied:
            lines.append(f"  {action.op} -> {action.target} ({action.kind})")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
