"""Code-enforced action policy: the point a proposal must pass before it runs.

This is the core of alertward. The planner (scripted or a real model) only
*proposes* actions. Whether an action may auto-execute, must wait for a human,
or is refused is decided here in code, from the action's intrinsic risk class
and a target allowlist - never from the planner's say-so. A model cannot talk
its way past this because it never gets to set the verdict.

Three independent checks, in order:
  1. target scope  - the action's target must be inside the allowed service set
  2. risk class    - read_only auto-runs, state_change needs approval,
                     destructive (and any unknown op) is denied outright
  3. auto budget   - only a bounded number of actions may auto-execute per run
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .actions import ProposedAction

GuardVerdict = Literal["allow_auto", "needs_approval", "denied"]

# Closed set of denial reasons. Branching code reads these codes, never a
# human-readable string, so a typo can never silently change a decision.
DenyReason = Literal[
    "destructive_op",
    "unknown_target",
    "auto_budget_exceeded",
]


@dataclass(frozen=True)
class GuardDecision:
    """The verdict for one proposed action, with a machine-readable reason."""

    action: ProposedAction
    verdict: GuardVerdict
    reason: str
    deny_code: DenyReason | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action.to_dict(),
            "verdict": self.verdict,
            "reason": self.reason,
            "deny_code": self.deny_code,
        }


@dataclass
class ActionGuard:
    """Mediates every proposed action against a fixed, code-level policy."""

    allowed_services: frozenset[str]
    max_auto_actions: int = 3
    _auto_count: int = field(default=0, init=False)

    def evaluate(self, action: ProposedAction) -> GuardDecision:
        """Decide a single action. Pure except for the auto-budget counter."""

        # 1. Target scope. An action aimed at a service we do not own is
        #    refused before risk is even considered.
        if action.target not in self.allowed_services:
            return GuardDecision(
                action=action,
                verdict="denied",
                reason=f"target '{action.target}' is outside the allowed service scope",
                deny_code="unknown_target",
            )

        # 2. Risk class. Destructive ops - and anything not on a known list,
        #    which classify_op maps to destructive - are always denied. They
        #    are never auto-run and never even queued for approval here,
        #    because chain-of-custody for production changes means a refusal,
        #    not a maybe.
        if action.kind == "destructive":
            return GuardDecision(
                action=action,
                verdict="denied",
                reason=f"op '{action.op}' is destructive and cannot be auto-executed",
                deny_code="destructive_op",
            )

        # State changes mutate the system: always route to a human.
        if action.kind == "state_change":
            return GuardDecision(
                action=action,
                verdict="needs_approval",
                reason=f"op '{action.op}' changes state and requires human approval",
            )

        # 3. Auto budget. Read-only actions are safe, but a runaway loop should
        #    not be able to fire an unbounded number of them per run.
        if self._auto_count >= self.max_auto_actions:
            return GuardDecision(
                action=action,
                verdict="denied",
                reason=f"auto-action budget of {self.max_auto_actions} exhausted this run",
                deny_code="auto_budget_exceeded",
            )

        self._auto_count += 1
        return GuardDecision(
            action=action,
            verdict="allow_auto",
            reason=f"op '{action.op}' is read-only and within budget",
        )

    @property
    def auto_used(self) -> int:
        return self._auto_count
