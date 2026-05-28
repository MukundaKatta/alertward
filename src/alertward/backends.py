"""Planner backends.

A backend turns an incident into a *proposed* remediation action. The default
``StubBackend`` is deterministic and keyless, so the whole loop runs offline
and the tests are reproducible. The optional Gemini/Anthropic/Ollama backends
are imported lazily so importing this module never pulls in an SDK you do not
have installed.

Crucially, a backend only *proposes*. It cannot execute anything and it cannot
set a guard verdict - that authority lives in guardrails.py. A backend that
proposes a destructive op simply gets that op denied.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .actions import ProposedAction
from .alerts import Incident


@runtime_checkable
class Backend(Protocol):
    name: str

    def propose(self, incident: Incident) -> ProposedAction: ...


# Deterministic mapping from incident category to a safe first response. Every
# default proposal is read-only: gather context first, let a human decide on
# any state change.
_CATEGORY_PLAYBOOK: dict[str, tuple[str, str]] = {
    "availability": ("splunk_search", "pull 5xx breakdown by endpoint for the last 15m"),
    "latency": ("get_dashboard", "open the service latency dashboard for the window"),
    "security": ("splunk_search", "list source IPs and accounts for the auth failures"),
    "capacity": ("describe_host", "check disk and inode usage trend on the host"),
    "data_quality": ("tail_logs", "tail the pipeline logs for parse errors"),
    "unknown": ("fetch_runbook", "fetch the generic triage runbook"),
}


class StubBackend:
    """Keyless, deterministic planner used for the demo and tests."""

    name = "stub"

    def propose(self, incident: Incident) -> ProposedAction:
        op, rationale = _CATEGORY_PLAYBOOK.get(
            incident.category, _CATEGORY_PLAYBOOK["unknown"]
        )
        return ProposedAction(
            op=op,
            target=incident.service,
            rationale=rationale,
            args={"incident_id": incident.incident_id},
        )


class GeminiBackend:
    """Lazy Gemini planner (model gemini-2.5-flash, env GEMINI_API_KEY)."""

    name = "gemini"

    def __init__(self, model: str = "gemini-2.5-flash") -> None:
        self.model = model

    def propose(self, incident: Incident) -> ProposedAction:  # pragma: no cover
        import os

        from google import genai  # type: ignore

        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        prompt = _planner_prompt(incident)
        resp = client.models.generate_content(model=self.model, contents=prompt)
        return _parse_proposal(resp.text or "", incident)


class AnthropicBackend:
    """Lazy Anthropic planner (model claude-sonnet-4-6, env ANTHROPIC_API_KEY)."""

    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-6") -> None:
        self.model = model

    def propose(self, incident: Incident) -> ProposedAction:  # pragma: no cover
        import anthropic  # type: ignore

        client = anthropic.Anthropic()
        msg = client.messages.create(
            model=self.model,
            max_tokens=512,
            messages=[{"role": "user", "content": _planner_prompt(incident)}],
        )
        text = "".join(b.text for b in msg.content if b.type == "text")
        return _parse_proposal(text, incident)


class OllamaBackend:
    """Lazy local Ollama planner (model llama3.2, localhost:11434)."""

    name = "ollama"

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model

    def propose(self, incident: Incident) -> ProposedAction:  # pragma: no cover
        import ollama  # type: ignore

        resp = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": _planner_prompt(incident)}],
        )
        return _parse_proposal(resp["message"]["content"], incident)


def _planner_prompt(incident: Incident) -> str:
    return (
        "You are an SRE triage assistant. Propose ONE next action for this "
        "incident as JSON with keys op, target, rationale. Prefer read-only "
        "ops (splunk_search, get_dashboard, describe_host, tail_logs, "
        "fetch_runbook). Never propose destructive ops.\n\n"
        f"Incident: {incident.to_dict()}"
    )


def _parse_proposal(text: str, incident: Incident) -> ProposedAction:  # pragma: no cover
    """Tolerant JSON extraction; falls back to the stub on any parse issue."""

    import json
    import re

    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group(0))
            return ProposedAction(
                op=str(obj.get("op", "fetch_runbook")),
                target=str(obj.get("target", incident.service)),
                rationale=str(obj.get("rationale", "model proposal")),
                args={"incident_id": incident.incident_id},
            )
        except (ValueError, TypeError):
            pass
    return StubBackend().propose(incident)
