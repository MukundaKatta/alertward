"""Stub backend is deterministic and satisfies the Backend protocol."""

from __future__ import annotations

import _bootstrap  # noqa: F401  (side effect: puts src/ on sys.path)
from alertward.actions import classify_op
from alertward.alerts import Incident
from alertward.backends import (
    AnthropicBackend,
    Backend,
    GeminiBackend,
    OllamaBackend,
    StubBackend,
)


def make_incident(category: str, service: str = "checkout-api") -> Incident:
    return Incident(
        incident_id="INC-001",
        service=service,
        category=category,  # type: ignore[arg-type]
        severity="high",
        alert_ids=["A-1"],
        summary="x",
    )


def test_stub_satisfies_backend_protocol():
    assert isinstance(StubBackend(), Backend)


def test_real_backends_satisfy_protocol_without_sdk():
    # Constructing them must not import any SDK.
    for backend in (GeminiBackend(), AnthropicBackend(), OllamaBackend()):
        assert isinstance(backend, Backend)
        assert backend.name in {"gemini", "anthropic", "ollama"}


def test_stub_proposals_are_always_read_only():
    stub = StubBackend()
    for category in ("availability", "latency", "security", "capacity", "unknown"):
        action = stub.propose(make_incident(category))
        assert classify_op(action.op) == "read_only", category


def test_stub_is_deterministic():
    stub = StubBackend()
    inc = make_incident("security")
    first = stub.propose(inc).to_dict()
    second = stub.propose(inc).to_dict()
    assert first == second


def test_stub_targets_the_incident_service():
    action = StubBackend().propose(make_incident("latency", service="orders-db"))
    assert action.target == "orders-db"
