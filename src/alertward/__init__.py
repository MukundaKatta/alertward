"""alertward - a guarded, audited incident-triage agent for agentic ops.

The planner proposes; code decides. Destructive remediation can never be
auto-executed, state changes always route to a human, and every step is
written to a replayable JSONL audit trail.
"""

from __future__ import annotations

from .actions import (
    DESTRUCTIVE_OPS,
    READ_ONLY_OPS,
    STATE_CHANGE_OPS,
    ProposedAction,
    classify_op,
)
from .alerts import Alert, Incident, sample_alert_stream
from .audit import AuditLog
from .backends import (
    AnthropicBackend,
    Backend,
    GeminiBackend,
    OllamaBackend,
    StubBackend,
)
from .guardrails import ActionGuard, GuardDecision
from .pipeline import TriagePipeline, TriageResult
from .report import render_report
from .triage import correlate

__version__ = "0.1.0"

__all__ = [
    "Alert",
    "Incident",
    "sample_alert_stream",
    "ProposedAction",
    "classify_op",
    "READ_ONLY_OPS",
    "STATE_CHANGE_OPS",
    "DESTRUCTIVE_OPS",
    "AuditLog",
    "Backend",
    "StubBackend",
    "GeminiBackend",
    "AnthropicBackend",
    "OllamaBackend",
    "ActionGuard",
    "GuardDecision",
    "TriagePipeline",
    "TriageResult",
    "render_report",
    "correlate",
    "__version__",
]


def default_allowed_services() -> frozenset[str]:
    """Services the bundled demo stream is scoped to operate on."""

    return frozenset(
        {
            "checkout-api",
            "orders-db",
            "ssh",
            "log-pipeline",
        }
    )
