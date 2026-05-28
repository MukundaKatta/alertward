"""The guard is the safety property; these tests are the proof of it."""

from __future__ import annotations

from alertward.actions import ProposedAction
from alertward.guardrails import ActionGuard

SCOPE = frozenset({"checkout-api", "orders-db"})


def make_guard(max_auto: int = 3) -> ActionGuard:
    return ActionGuard(allowed_services=SCOPE, max_auto_actions=max_auto)


def test_read_only_action_auto_allowed():
    guard = make_guard()
    action = ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
    decision = guard.evaluate(action)
    assert decision.verdict == "allow_auto"
    assert decision.deny_code is None


def test_state_change_always_needs_approval():
    guard = make_guard()
    action = ProposedAction(op="scale_up", target="checkout-api", rationale="x")
    decision = guard.evaluate(action)
    assert decision.verdict == "needs_approval"
    assert decision.deny_code is None


def test_destructive_action_is_always_denied():
    guard = make_guard()
    for op in ["restart_service", "scale_down", "failover_db", "delete_index"]:
        action = ProposedAction(op=op, target="checkout-api", rationale="urgent")
        decision = guard.evaluate(action)
        assert decision.verdict == "denied", op
        assert decision.deny_code == "destructive_op", op


def test_unknown_op_defaults_to_destructive_and_is_denied():
    """A planner inventing an op cannot sneak it through as safe."""
    guard = make_guard()
    action = ProposedAction(op="rm_minus_rf", target="checkout-api", rationale="x")
    decision = guard.evaluate(action)
    assert decision.verdict == "denied"
    assert decision.deny_code == "destructive_op"


def test_out_of_scope_target_is_denied_before_risk():
    guard = make_guard()
    # Even a read-only op is refused if the target is outside the allowed set.
    action = ProposedAction(op="splunk_search", target="payroll-db", rationale="x")
    decision = guard.evaluate(action)
    assert decision.verdict == "denied"
    assert decision.deny_code == "unknown_target"


def test_auto_budget_is_enforced():
    guard = make_guard(max_auto=2)
    a = ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
    assert guard.evaluate(a).verdict == "allow_auto"
    assert guard.evaluate(a).verdict == "allow_auto"
    third = guard.evaluate(a)
    assert third.verdict == "denied"
    assert third.deny_code == "auto_budget_exceeded"
    assert guard.auto_used == 2


def test_approval_and_denial_do_not_consume_auto_budget():
    guard = make_guard(max_auto=1)
    guard.evaluate(ProposedAction(op="scale_up", target="checkout-api", rationale="x"))
    guard.evaluate(ProposedAction(op="drain_node", target="checkout-api", rationale="x"))
    # The one read-only slot is still available.
    decision = guard.evaluate(
        ProposedAction(op="get_dashboard", target="checkout-api", rationale="x")
    )
    assert decision.verdict == "allow_auto"
    assert guard.auto_used == 1
