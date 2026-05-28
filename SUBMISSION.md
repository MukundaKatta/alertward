# Splunk Agentic Ops — submission copy (alertward)

Event: Splunk Agentic Ops (Devpost) — agentic AI for observability and
security operations. ~$20K, sponsor Cisco. Deadline 2026-06-15 09:00 PDT.
Teams up to 2, solo OK.

Repo: https://github.com/MukundaKatta/alertward

> Eligibility note to confirm at submit time: some Devpost ops hackathons
> exclude Brazil and Quebec residents. US/India solo entry is fine. Re-check the
> official rules page before filing.

## Tagline

    A guarded incident-triage agent for agentic ops: the planner proposes,
    code decides, and destructive remediation can never auto-run.

## Short description

    alertward turns a stream of observability and security alerts into
    correlated incidents and drives a plan-decide-execute loop over them. For
    each incident a planner (a real model, or a deterministic offline stub)
    proposes one next action. Whether that action auto-runs, waits for a human,
    or is refused is decided in code - not in a prompt - from the action's
    intrinsic risk class and a target allowlist. Every step is written to a
    replayable JSONL audit trail. The whole loop runs offline with no API key
    and no Splunk instance, so a judge can verify it in one command.

## Inspiration

    Most "autonomous ops" demos put "do not restart prod" in a system prompt
    and hope the model complies. For anything touching production that is not a
    control, it is a suggestion. We wanted an ops agent that does not trust the
    model at all: the safety properties are architectural, and the entire
    triage run is auditable line by line.

## What it does

    It ingests alerts (offline, a synthetic Splunk-style stream; in production,
    a saved-search export, an alert-action webhook, or the HTTP Event
    Collector), correlates alerts that share a service/signal fingerprint into
    incidents, and classifies each incident's severity and category
    (availability, latency, security, capacity, data quality). For each
    incident the planner proposes one remediation action. The guard then
    decides:

      - read-only context-gathering ops (splunk_search, get_dashboard,
        tail_logs, describe_host, fetch_runbook) auto-execute, within a budget;
      - state-changing ops (scale_up, rotate_credentials, block_ip,
        open_incident_ticket) always route to a human for approval;
      - destructive ops (restart_service, scale_down, drain_node, failover_db,
        delete_index, rollback_deploy, terminate_instance) - and any unknown
        op - are denied outright and never run.

    It produces an ops-ready triage report (incidents ranked by severity, the
    proposed action per incident, and the guard verdict with a machine-readable
    reason), plus a flushed JSONL audit trail of every step.

## How we built it

    The agent is a deterministic plan-decide-execute state machine. Two ideas
    carry the project:

    1. The guard is code, not a prompt. guardrails.py is the policy enforcement
       point between planner and execution. An action's risk class is intrinsic
       to the action type (actions.py), not something the planner asserts, and
       unknown ops default to "destructive" so anything unvetted is treated as
       the most dangerous class. Three independent checks run in order: target
       scope (an allowlist of services the agent may touch), risk class, and a
       per-run auto-execution budget. Deny reasons are a closed Literal union,
       not free-form strings, so a typo can never silently flip a decision.

    2. Every transition is auditable. audit.py writes one flushed JSONL record
       per step (run_start, incident, proposal, decision, execution, report,
       run_end), so the trail survives a crash and the run can be replayed and
       graded.

    The planner is a Backend - a runtime-checkable Protocol with one method,
    propose(). The default StubBackend is keyless and deterministic; optional
    Gemini, Anthropic, and Ollama backends are imported lazily so importing the
    package never pulls in an SDK you do not have. Whatever a real model
    proposes still passes through the same guard.

## Challenges we ran into

    Making the guard genuinely unbypassable rather than advisory. The key move
    was putting risk on the action type and defaulting unknown ops to
    destructive, so a planner cannot invent a benign-sounding op to slip a
    dangerous one through. Keeping the loop deterministic so the demo and tests
    reproduce exactly, and scoring the guard honestly: the test suite includes
    a "rogue" planner that proposes restart_service on every incident and
    proves nothing executes.

## Accomplishments we're proud of

    The entire guarded loop, all three guard checks, the audit trail, and the
    report run offline and deterministically. 26 tests pass with no API key and
    no Splunk instance. The safety property - destructive remediation can never
    auto-run - is provable by reading the code and the guard tests, not by
    trusting a prompt.

## What we learned

    For agentic ops, the value is in enforced constraints and audit quality,
    not in a clever prompt. If "don't touch prod" is a policy the model can
    override, it is not a control.

## What's next (needs the real environment)

    Honest scope. Done and verifiable now with no account and no VM: the full
    loop, the guard, the audit trail, the report, the CLI, the dashboard, and
    26 green tests. Still to demonstrate against live data: wiring the read-only
    ops to a real Splunk instance (REST API / saved searches / HEC), running
    the loop against real fired alerts, and a short demo video. The offline
    StubBackend and synthetic alert stream exist so everything else is provable
    without these.

## Tech tags

    python, agentic-ops, observability, incident-response, sre, splunk,
    security-operations, guardrails, audit-log, llm, anthropic, gemini, ollama,
    mit

## Links

  - Repo: https://github.com/MukundaKatta/alertward
  - 60-second offline proof: `pip install -e . && python examples/demo.py`
  - Tests: `python -m pytest -q` (26, offline, deterministic)
  - Dashboard: `pip install -e ".[dashboard]" && streamlit run app.py`

## Submission requirement checklist

  - [x] Public repo, working code, offline-verifiable (26 tests green)
  - [x] Agentic ops use case (alert -> incident -> guarded remediation)
  - [ ] Live run wired to a real Splunk instance — USER TODO (needs Splunk)
  - [ ] Demo video of a run — USER TODO
  - [ ] Confirm region eligibility (Brazil/Quebec exclusion) before final submit
