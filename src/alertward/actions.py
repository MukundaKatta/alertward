"""Proposed remediation actions and their risk classification.

An action's `kind` is intrinsic to the action, not a suggestion from the
planner. The guard (guardrails.py) reads the kind to decide whether the action
may auto-execute, must wait for a human, or is refused outright. Keeping the
risk class on the action type (not in a free-form string) is what makes the
policy enforceable rather than advisory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ActionKind = Literal["read_only", "state_change", "destructive"]

# Read-only ops are safe to run unattended: they only gather more context.
READ_ONLY_OPS: frozenset[str] = frozenset(
    {
        "splunk_search",
        "get_dashboard",
        "describe_host",
        "list_recent_deploys",
        "fetch_runbook",
        "tail_logs",
    }
)

# State changes are reversible-ish but still mutate the system, so they need a
# human in the loop before they run.
STATE_CHANGE_OPS: frozenset[str] = frozenset(
    {
        "scale_up",
        "rotate_credentials",
        "open_incident_ticket",
        "silence_alert",
        "block_ip",
    }
)

# Destructive ops can cause an outage or lose data. They are never auto-run by
# this agent; they exist so a proposal naming one is explicitly refused.
DESTRUCTIVE_OPS: frozenset[str] = frozenset(
    {
        "restart_service",
        "scale_down",
        "drain_node",
        "failover_db",
        "delete_index",
        "rollback_deploy",
        "terminate_instance",
    }
)


def classify_op(op: str) -> ActionKind:
    """Map an operation name to its intrinsic risk class.

    Unknown operations default to ``destructive`` so that anything the policy
    has not explicitly vetted is treated as the most dangerous class rather
    than slipping through as safe.
    """

    if op in READ_ONLY_OPS:
        return "read_only"
    if op in STATE_CHANGE_OPS:
        return "state_change"
    return "destructive"


@dataclass(frozen=True)
class ProposedAction:
    """A remediation step a planner wants to take for an incident."""

    op: str
    target: str
    rationale: str
    args: dict[str, str] = field(default_factory=dict)

    @property
    def kind(self) -> ActionKind:
        return classify_op(self.op)

    def to_dict(self) -> dict[str, object]:
        return {
            "op": self.op,
            "target": self.target,
            "rationale": self.rationale,
            "args": dict(self.args),
            "kind": self.kind,
        }
