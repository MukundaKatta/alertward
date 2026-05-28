"""The guarded triage loop: alerts in, an audited TriageResult out.

For each correlated incident the pipeline asks the planner for one proposed
action, runs that proposal through the ActionGuard, and only "executes" it
(here, records an execution stub) when the guard returns ``allow_auto``.
state_change proposals are parked for human approval; destructive and
out-of-scope proposals are denied. Every step is written to the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .actions import ProposedAction
from .alerts import Alert, Incident
from .audit import AuditLog
from .backends import Backend, StubBackend
from .guardrails import ActionGuard, GuardDecision
from .triage import correlate


@dataclass
class TriageResult:
    incidents: list[Incident] = field(default_factory=list)
    decisions: list[GuardDecision] = field(default_factory=list)
    executed: list[ProposedAction] = field(default_factory=list)
    pending_approval: list[ProposedAction] = field(default_factory=list)
    denied: list[ProposedAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "incidents": [i.to_dict() for i in self.incidents],
            "decisions": [d.to_dict() for d in self.decisions],
            "executed": [a.to_dict() for a in self.executed],
            "pending_approval": [a.to_dict() for a in self.pending_approval],
            "denied": [a.to_dict() for a in self.denied],
        }


@dataclass
class TriagePipeline:
    guard: ActionGuard
    backend: Backend = field(default_factory=StubBackend)
    audit: AuditLog = field(default_factory=AuditLog)

    def run(self, alerts: list[Alert]) -> TriageResult:
        self.audit.record(
            "run_start",
            {"alert_count": len(alerts), "backend": self.backend.name},
        )

        incidents = correlate(alerts)
        result = TriageResult(incidents=incidents)

        for incident in incidents:
            self.audit.record("incident", incident.to_dict())

            action = self.backend.propose(incident)
            self.audit.record(
                "proposal",
                {"incident_id": incident.incident_id, **action.to_dict()},
            )

            decision = self.guard.evaluate(action)
            result.decisions.append(decision)
            self.audit.record(
                "decision",
                {"incident_id": incident.incident_id, **decision.to_dict()},
            )

            if decision.verdict == "allow_auto":
                # Real deployments would invoke the read-only tool here. Offline
                # we record the execution so the trail is complete.
                result.executed.append(action)
                self.audit.record(
                    "execution",
                    {"incident_id": incident.incident_id, "op": action.op},
                )
            elif decision.verdict == "needs_approval":
                result.pending_approval.append(action)
            else:
                result.denied.append(action)

        self.audit.record(
            "report",
            {
                "incidents": len(result.incidents),
                "executed": len(result.executed),
                "pending_approval": len(result.pending_approval),
                "denied": len(result.denied),
            },
        )
        self.audit.record("run_end", {"auto_used": self.guard.auto_used})
        return result
