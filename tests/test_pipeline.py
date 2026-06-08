"""End-to-end guarded loop, fully offline and deterministic."""

from __future__ import annotations

import _bootstrap  # noqa: F401  (side effect: puts src/ on sys.path)
from alertward import (
    ActionGuard,
    ProposedAction,
    StubBackend,
    TriagePipeline,
    default_allowed_services,
    render_report,
    sample_alert_stream,
)
from alertward.alerts import Incident
from alertward.audit import AuditLog


def build_pipeline(max_auto: int = 3, backend=None) -> TriagePipeline:
    return TriagePipeline(
        guard=ActionGuard(
            allowed_services=default_allowed_services(),
            max_auto_actions=max_auto,
        ),
        backend=backend or StubBackend(),
        audit=AuditLog(),
    )


def test_stub_run_is_deterministic():
    result = build_pipeline().run(sample_alert_stream())
    # 4 incidents; stub proposes read-only for all; budget of 3 auto-runs,
    # so 3 execute and the 4th is denied for budget.
    assert len(result.incidents) == 4
    assert len(result.executed) == 3
    assert len(result.pending_approval) == 0
    assert len(result.denied) == 1
    assert result.denied[0].target == "log-pipeline"
    budget_decisions = [
        d for d in result.decisions if d.deny_code == "auto_budget_exceeded"
    ]
    assert len(budget_decisions) == 1


def test_audit_trail_covers_every_step():
    pipeline = build_pipeline()
    pipeline.run(sample_alert_stream())
    counts = pipeline.audit.counts()
    assert counts["run_start"] == 1
    assert counts["incident"] == 4
    assert counts["proposal"] == 4
    assert counts["decision"] == 4
    assert counts["execution"] == 3
    assert counts["run_end"] == 1


def test_destructive_proposal_is_denied_not_executed():
    class RogueBackend:
        name = "rogue"

        def propose(self, incident: Incident) -> ProposedAction:
            # A misbehaving planner that always wants to restart prod.
            return ProposedAction(
                op="restart_service",
                target=incident.service,
                rationale="just restart it",
            )

    result = build_pipeline(backend=RogueBackend()).run(sample_alert_stream())
    assert len(result.executed) == 0
    assert len(result.denied) == 4
    assert all(d.deny_code == "destructive_op" for d in result.decisions)


def test_state_change_proposal_parks_for_approval():
    class CautiousBackend:
        name = "cautious"

        def propose(self, incident: Incident) -> ProposedAction:
            return ProposedAction(
                op="open_incident_ticket",
                target=incident.service,
                rationale="page the on-call",
            )

    result = build_pipeline(backend=CautiousBackend()).run(sample_alert_stream())
    assert len(result.executed) == 0
    assert len(result.pending_approval) == 4
    assert all(d.verdict == "needs_approval" for d in result.decisions)


def test_report_renders_without_error():
    result = build_pipeline().run(sample_alert_stream())
    text = render_report(result)
    assert "ALERTWARD TRIAGE REPORT" in text
    assert "INC-" in text
