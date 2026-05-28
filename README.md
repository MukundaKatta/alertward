# alertward

A guarded, audited incident-triage agent for agentic ops. The planner proposes,
**code decides**, destructive remediation can never auto-run, and every step is
written to a replayable JSONL audit trail.

[![tests](https://img.shields.io/badge/tests-offline-green)](#run-the-tests)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## Why

Most "autonomous ops" demos put *"don't restart prod"* in a system prompt and
hope the model behaves. In production that is not a control. alertward does not
trust the planner at all: it can only **propose** an action, and whether that
action auto-runs, waits for a human, or is refused is decided in code, from the
action's intrinsic risk class and a target allowlist. A model cannot talk its
way past the guard because it never gets to set the verdict.

## The guarded loop

```
alerts -> correlate into incidents -> planner proposes one action per incident
       -> ActionGuard.evaluate(action) -> {allow_auto | needs_approval | denied}
       -> execute only if allow_auto -> JSONL audit record at every step
```

Three independent checks in `guardrails.py`, in order:

1. **Target scope** - the action's target must be inside the allowed service
   set, or it is denied (`unknown_target`) before risk is even considered.
2. **Risk class** - `read_only` ops auto-run; `state_change` ops always route to
   a human (`needs_approval`); `destructive` ops, and any **unknown** op (which
   defaults to destructive), are denied outright (`destructive_op`).
3. **Auto budget** - only a bounded number of read-only actions may auto-execute
   per run, so a runaway loop cannot spam (`auto_budget_exceeded`).

Deny reasons are a closed `Literal` union, not free-form strings, so a typo can
never silently flip a decision.

## 60-second offline proof

```bash
pip install -e .
python examples/demo.py     # or: alertward
```

No API key, no Splunk instance. The stub planner and a synthetic alert stream
make the whole run deterministic. You will see four incidents (an ssh
brute-force leads, being critical), three read-only actions auto-executed, the
fourth denied for budget, and the audit step counts.

## Run the tests

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The suite is fully offline and deterministic. The guard tests are the proof of
the safety property: a planner that proposes `restart_service` on every incident
gets every proposal denied and nothing executed.

## Backends

The planner is a `Backend` (a `@runtime_checkable` Protocol with one method,
`propose`). The default `StubBackend` is keyless and deterministic. Optional
real planners are imported lazily so importing the package never pulls in an
SDK you do not have:

| backend            | model              | env                |
| ------------------ | ------------------ | ------------------ |
| `StubBackend`      | none (deterministic) | -                |
| `GeminiBackend`    | gemini-2.5-flash   | `GEMINI_API_KEY`   |
| `AnthropicBackend` | claude-sonnet-4-6  | `ANTHROPIC_API_KEY`|
| `OllamaBackend`    | llama3.2 (local)   | -                  |

```bash
alertward --backend gemini --audit runs/triage.jsonl
```

Whatever the planner proposes still passes through the same guard. A real model
that suggests a destructive remediation is denied exactly like the stub test.

## Dashboard

```bash
pip install -e ".[dashboard]"
streamlit run app.py
```

## Connecting real Splunk (not included)

Offline, alerts come from `sample_alert_stream()`. In a live deployment they
arrive from Splunk - a saved-search export, an alert-action webhook, or the HTTP
Event Collector - and the read-only ops (`splunk_search`, `get_dashboard`,
`tail_logs`) map to real Splunk REST calls. Wiring that to a live Splunk
instance and recording a run against real alerts is the remaining
environment-dependent step.

## Layout

```
src/alertward/
  alerts.py      Alert + Incident types and the synthetic stream
  actions.py     ProposedAction + intrinsic risk classification
  guardrails.py  ActionGuard: the code-enforced policy (the core)
  triage.py      correlate alerts into incidents, classify severity/category
  backends.py    Backend protocol + StubBackend + lazy Gemini/Anthropic/Ollama
  audit.py       flushed JSONL audit trail
  pipeline.py    the guarded plan-decide-execute loop
  report.py      ops-ready text report
  cli.py         `alertward` command
tests/           fully offline, deterministic
examples/demo.py offline demo
app.py           Streamlit dashboard
```

## License

MIT
