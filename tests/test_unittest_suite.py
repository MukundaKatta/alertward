"""Standard-library ``unittest`` suite that exercises the real code.

The companion ``test_*.py`` files in this directory are written for ``pytest``
and require its fixtures (``tmp_path``) to run. This module covers the same
behavior using only the Python standard library so the safety properties can be
verified with zero third-party dependencies:

    python3 -m unittest discover -s tests

It imports and runs the actual package - the guard, correlation, the pipeline,
the audit trail, the report renderer, the CLI, and the stub backend - rather
than re-implementing any logic.
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import _bootstrap  # noqa: F401  (side effect: puts src/ on sys.path)
from alertward import (
    ActionGuard,
    Alert,
    AuditLog,
    Backend,
    Incident,
    ProposedAction,
    StubBackend,
    TriagePipeline,
    classify_op,
    correlate,
    default_allowed_services,
    render_report,
    sample_alert_stream,
)
from alertward.actions import DESTRUCTIVE_OPS, READ_ONLY_OPS, STATE_CHANGE_OPS
from alertward.backends import AnthropicBackend, GeminiBackend, OllamaBackend
from alertward.cli import main as cli_main

SCOPE = frozenset({"checkout-api", "orders-db"})


def make_guard(max_auto: int = 3) -> ActionGuard:
    return ActionGuard(allowed_services=SCOPE, max_auto_actions=max_auto)


def make_incident(category: str, service: str = "checkout-api") -> Incident:
    return Incident(
        incident_id="INC-001",
        service=service,
        category=category,  # type: ignore[arg-type]
        severity="high",
        alert_ids=["A-1"],
        summary="x",
    )


class ClassifyOpTests(unittest.TestCase):
    def test_known_op_lists_are_disjoint(self) -> None:
        self.assertEqual(READ_ONLY_OPS & STATE_CHANGE_OPS, frozenset())
        self.assertEqual(READ_ONLY_OPS & DESTRUCTIVE_OPS, frozenset())
        self.assertEqual(STATE_CHANGE_OPS & DESTRUCTIVE_OPS, frozenset())

    def test_classify_each_known_op(self) -> None:
        for op in READ_ONLY_OPS:
            self.assertEqual(classify_op(op), "read_only", op)
        for op in STATE_CHANGE_OPS:
            self.assertEqual(classify_op(op), "state_change", op)
        for op in DESTRUCTIVE_OPS:
            self.assertEqual(classify_op(op), "destructive", op)

    def test_unknown_op_defaults_to_destructive(self) -> None:
        self.assertEqual(classify_op("rm_minus_rf"), "destructive")
        self.assertEqual(classify_op(""), "destructive")

    def test_proposed_action_kind_and_to_dict(self) -> None:
        action = ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
        self.assertEqual(action.kind, "read_only")
        d = action.to_dict()
        self.assertEqual(d["op"], "splunk_search")
        self.assertEqual(d["kind"], "read_only")
        self.assertEqual(d["args"], {})
        # to_dict copies args rather than aliasing the internal dict.
        d["args"]["mutated"] = "yes"  # type: ignore[index]
        self.assertEqual(action.args, {})


class GuardTests(unittest.TestCase):
    """The guard is the safety property; these are the proof of it."""

    def test_read_only_action_auto_allowed(self) -> None:
        decision = make_guard().evaluate(
            ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
        )
        self.assertEqual(decision.verdict, "allow_auto")
        self.assertIsNone(decision.deny_code)

    def test_state_change_always_needs_approval(self) -> None:
        decision = make_guard().evaluate(
            ProposedAction(op="scale_up", target="checkout-api", rationale="x")
        )
        self.assertEqual(decision.verdict, "needs_approval")
        self.assertIsNone(decision.deny_code)

    def test_destructive_action_is_always_denied(self) -> None:
        guard = make_guard()
        for op in ["restart_service", "scale_down", "failover_db", "delete_index"]:
            decision = guard.evaluate(
                ProposedAction(op=op, target="checkout-api", rationale="urgent")
            )
            self.assertEqual(decision.verdict, "denied", op)
            self.assertEqual(decision.deny_code, "destructive_op", op)

    def test_unknown_op_cannot_sneak_through_as_safe(self) -> None:
        decision = make_guard().evaluate(
            ProposedAction(op="totally_safe_promise", target="checkout-api", rationale="x")
        )
        self.assertEqual(decision.verdict, "denied")
        self.assertEqual(decision.deny_code, "destructive_op")

    def test_out_of_scope_target_denied_before_risk(self) -> None:
        # Even a read-only op is refused if the target is outside the allow set.
        decision = make_guard().evaluate(
            ProposedAction(op="splunk_search", target="payroll-db", rationale="x")
        )
        self.assertEqual(decision.verdict, "denied")
        self.assertEqual(decision.deny_code, "unknown_target")

    def test_out_of_scope_destructive_reports_target_first(self) -> None:
        # Scope is checked before risk: a destructive op aimed off-scope is
        # denied for the target, not the risk class.
        decision = make_guard().evaluate(
            ProposedAction(op="restart_service", target="payroll-db", rationale="x")
        )
        self.assertEqual(decision.deny_code, "unknown_target")

    def test_auto_budget_is_enforced(self) -> None:
        guard = make_guard(max_auto=2)
        a = ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
        self.assertEqual(guard.evaluate(a).verdict, "allow_auto")
        self.assertEqual(guard.evaluate(a).verdict, "allow_auto")
        third = guard.evaluate(a)
        self.assertEqual(third.verdict, "denied")
        self.assertEqual(third.deny_code, "auto_budget_exceeded")
        self.assertEqual(guard.auto_used, 2)

    def test_zero_budget_denies_first_read_only(self) -> None:
        decision = make_guard(max_auto=0).evaluate(
            ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
        )
        self.assertEqual(decision.verdict, "denied")
        self.assertEqual(decision.deny_code, "auto_budget_exceeded")

    def test_approval_and_denial_do_not_consume_budget(self) -> None:
        guard = make_guard(max_auto=1)
        guard.evaluate(ProposedAction(op="scale_up", target="checkout-api", rationale="x"))
        guard.evaluate(ProposedAction(op="drain_node", target="checkout-api", rationale="x"))
        decision = guard.evaluate(
            ProposedAction(op="get_dashboard", target="checkout-api", rationale="x")
        )
        self.assertEqual(decision.verdict, "allow_auto")
        self.assertEqual(guard.auto_used, 1)

    def test_decision_to_dict_is_json_serializable(self) -> None:
        decision = make_guard().evaluate(
            ProposedAction(op="splunk_search", target="checkout-api", rationale="x")
        )
        # Must round-trip through JSON for the audit trail.
        json.dumps(decision.to_dict())


class CorrelationTests(unittest.TestCase):
    def test_folds_shared_fingerprint(self) -> None:
        incidents = correlate(sample_alert_stream())
        checkout = [i for i in incidents if i.service == "checkout-api"]
        self.assertEqual(len(checkout), 1)
        self.assertEqual(set(checkout[0].alert_ids), {"A-1001", "A-1002"})

    def test_sample_stream_yields_four_incidents(self) -> None:
        incidents = correlate(sample_alert_stream())
        self.assertEqual(len(incidents), 4)
        self.assertEqual(
            {i.service for i in incidents},
            {"checkout-api", "orders-db", "ssh", "log-pipeline"},
        )

    def test_sorted_most_severe_first(self) -> None:
        incidents = correlate(sample_alert_stream())
        self.assertEqual(incidents[0].service, "ssh")
        self.assertEqual(incidents[0].severity, "critical")
        self.assertEqual(incidents[0].category, "security")

    def test_category_mapping(self) -> None:
        by_service = {i.service: i for i in correlate(sample_alert_stream())}
        self.assertEqual(by_service["checkout-api"].category, "availability")
        self.assertEqual(by_service["orders-db"].category, "latency")
        self.assertEqual(by_service["log-pipeline"].category, "capacity")

    def test_severity_is_max_of_members(self) -> None:
        by_service = {i.service: i for i in correlate(sample_alert_stream())}
        self.assertEqual(by_service["checkout-api"].severity, "high")

    def test_unknown_signal_maps_to_unknown_category(self) -> None:
        alert = Alert(
            alert_id="A-X",
            source="custom",
            host="h1",
            service="svc",
            message="m",
            raw_severity="low",
            fired_at="2026-06-01T09:00:00+00:00",
            signal="never_seen_before",
        )
        incidents = correlate([alert])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].category, "unknown")

    def test_empty_stream_yields_no_incidents(self) -> None:
        self.assertEqual(correlate([]), [])


class StubBackendTests(unittest.TestCase):
    def test_stub_satisfies_protocol(self) -> None:
        self.assertIsInstance(StubBackend(), Backend)

    def test_real_backends_satisfy_protocol_without_sdk(self) -> None:
        # Constructing them must not import any optional SDK.
        for backend in (GeminiBackend(), AnthropicBackend(), OllamaBackend()):
            self.assertIsInstance(backend, Backend)
            self.assertIn(backend.name, {"gemini", "anthropic", "ollama"})

    def test_stub_proposals_are_always_read_only(self) -> None:
        stub = StubBackend()
        for category in ("availability", "latency", "security", "capacity", "unknown"):
            action = stub.propose(make_incident(category))
            self.assertEqual(classify_op(action.op), "read_only", category)

    def test_stub_is_deterministic(self) -> None:
        stub = StubBackend()
        inc = make_incident("security")
        self.assertEqual(stub.propose(inc).to_dict(), stub.propose(inc).to_dict())

    def test_stub_targets_the_incident_service(self) -> None:
        action = StubBackend().propose(make_incident("latency", service="orders-db"))
        self.assertEqual(action.target, "orders-db")


class AuditTests(unittest.TestCase):
    def test_records_are_written_and_mirrored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            with AuditLog(path=log_path) as log:
                log.record("run_start", {"alert_count": 3})
                log.record("incident", {"incident_id": "INC-001"})
                log.record("run_end", {"auto_used": 1})
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 3)
            parsed = [json.loads(line) for line in lines]
            self.assertEqual(
                [p["step"] for p in parsed],
                ["run_start", "incident", "run_end"],
            )
            self.assertTrue(all("ts" in p for p in parsed))

    def test_flush_makes_partial_trail_readable_mid_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            log = AuditLog(path=log_path)
            try:
                log.record("run_start", {"alert_count": 1})
                # No close yet: a crash here must still leave line one on disk.
                lines = log_path.read_text(encoding="utf-8").strip().splitlines()
                self.assertEqual(len(lines), 1)
            finally:
                log.close()

    def test_parent_directories_are_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "nested" / "deeper" / "audit.jsonl"
            with AuditLog(path=log_path) as log:
                log.record("run_start", {})
            self.assertTrue(log_path.exists())

    def test_counts_groups_by_step(self) -> None:
        log = AuditLog()
        log.record("incident", {})
        log.record("incident", {})
        log.record("decision", {})
        self.assertEqual(log.counts(), {"incident": 2, "decision": 1})

    def test_memory_only_log_needs_no_file(self) -> None:
        log = AuditLog()
        entry = log.record("run_start", {"x": 1})
        self.assertEqual(entry["step"], "run_start")
        self.assertEqual(log.records, [entry])


class PipelineTests(unittest.TestCase):
    def build_pipeline(self, max_auto: int = 3, backend: Backend | None = None) -> TriagePipeline:
        return TriagePipeline(
            guard=ActionGuard(
                allowed_services=default_allowed_services(),
                max_auto_actions=max_auto,
            ),
            backend=backend or StubBackend(),
            audit=AuditLog(),
        )

    def test_stub_run_is_deterministic(self) -> None:
        result = self.build_pipeline().run(sample_alert_stream())
        self.assertEqual(len(result.incidents), 4)
        self.assertEqual(len(result.executed), 3)
        self.assertEqual(len(result.pending_approval), 0)
        self.assertEqual(len(result.denied), 1)
        self.assertEqual(result.denied[0].target, "log-pipeline")
        budget = [d for d in result.decisions if d.deny_code == "auto_budget_exceeded"]
        self.assertEqual(len(budget), 1)

    def test_audit_trail_covers_every_step(self) -> None:
        pipeline = self.build_pipeline()
        pipeline.run(sample_alert_stream())
        counts = pipeline.audit.counts()
        self.assertEqual(counts["run_start"], 1)
        self.assertEqual(counts["incident"], 4)
        self.assertEqual(counts["proposal"], 4)
        self.assertEqual(counts["decision"], 4)
        self.assertEqual(counts["execution"], 3)
        self.assertEqual(counts["run_end"], 1)

    def test_destructive_proposal_is_denied_not_executed(self) -> None:
        class RogueBackend:
            name = "rogue"

            def propose(self, incident: Incident) -> ProposedAction:
                return ProposedAction(
                    op="restart_service",
                    target=incident.service,
                    rationale="just restart it",
                )

        result = self.build_pipeline(backend=RogueBackend()).run(sample_alert_stream())
        self.assertEqual(len(result.executed), 0)
        self.assertEqual(len(result.denied), 4)
        self.assertTrue(all(d.deny_code == "destructive_op" for d in result.decisions))

    def test_state_change_proposal_parks_for_approval(self) -> None:
        class CautiousBackend:
            name = "cautious"

            def propose(self, incident: Incident) -> ProposedAction:
                return ProposedAction(
                    op="open_incident_ticket",
                    target=incident.service,
                    rationale="page the on-call",
                )

        result = self.build_pipeline(backend=CautiousBackend()).run(sample_alert_stream())
        self.assertEqual(len(result.executed), 0)
        self.assertEqual(len(result.pending_approval), 4)
        self.assertTrue(all(d.verdict == "needs_approval" for d in result.decisions))

    def test_result_to_dict_is_json_serializable(self) -> None:
        result = self.build_pipeline().run(sample_alert_stream())
        json.dumps(result.to_dict())


class ReportTests(unittest.TestCase):
    def _result(self):
        return TriagePipeline(
            guard=ActionGuard(allowed_services=default_allowed_services()),
            audit=AuditLog(),
        ).run(sample_alert_stream())

    def test_report_has_header_and_incidents(self) -> None:
        text = render_report(self._result())
        self.assertIn("ALERTWARD TRIAGE REPORT", text)
        self.assertIn("INC-", text)

    def test_report_ends_with_single_newline(self) -> None:
        text = render_report(self._result())
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))

    def test_report_lists_denied_section(self) -> None:
        text = render_report(self._result())
        self.assertIn("DENIED BY POLICY", text)


class CliTests(unittest.TestCase):
    def test_cli_stub_run_returns_zero_and_prints_report(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["--backend", "stub"])
        self.assertEqual(code, 0)
        self.assertIn("ALERTWARD TRIAGE REPORT", buf.getvalue())

    def test_cli_writes_audit_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "triage.jsonl"
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_main(["--audit", str(audit_path)])
            self.assertEqual(code, 0)
            self.assertTrue(audit_path.exists())
            lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertGreater(len(lines), 0)
            # Every line is valid JSON with a "step" key.
            for line in lines:
                self.assertIn("step", json.loads(line))

    def test_cli_max_auto_flag_changes_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "triage.jsonl"
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli_main(["--max-auto", "1", "--audit", str(audit_path)])
            records = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
            ]
            executions = [r for r in records if r["step"] == "execution"]
            # With a budget of 1, only one read-only action auto-executes.
            self.assertEqual(len(executions), 1)


if __name__ == "__main__":
    unittest.main()
