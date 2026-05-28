"""Streamlit dashboard for alertward.

    streamlit run app.py

Shows the synthetic alert stream, the correlated incidents, and the guard's
verdict for each proposed action, color-coded by outcome.
"""

from __future__ import annotations

import streamlit as st

from alertward import (
    ActionGuard,
    AuditLog,
    TriagePipeline,
    default_allowed_services,
    sample_alert_stream,
)

st.set_page_config(page_title="alertward", layout="wide")
st.title("alertward - guarded incident triage")
st.caption(
    "The planner proposes; code decides. Destructive remediation can never "
    "auto-run, state changes route to a human, every step is audited."
)

max_auto = st.sidebar.slider("Max auto-actions per run", 0, 6, 3)

alerts = sample_alert_stream()
pipeline = TriagePipeline(
    guard=ActionGuard(
        allowed_services=default_allowed_services(),
        max_auto_actions=max_auto,
    ),
    audit=AuditLog(),
)
result = pipeline.run(alerts)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Incidents", len(result.incidents))
c2.metric("Auto-executed", len(result.executed))
c3.metric("Awaiting approval", len(result.pending_approval))
c4.metric("Denied", len(result.denied))

st.subheader("Incidents and guard decisions")
by_incident = {d.action.args.get("incident_id"): d for d in result.decisions}
for inc in result.incidents:
    decision = by_incident.get(inc.incident_id)
    with st.expander(
        f"{inc.incident_id}  [{inc.severity.upper()}]  {inc.service}  ({inc.category})",
        expanded=inc.severity in ("critical", "high"),
    ):
        st.write(inc.summary)
        st.write("Alerts:", ", ".join(inc.alert_ids))
        if decision is not None:
            verdict = decision.verdict
            if verdict == "allow_auto":
                st.success(f"AUTO: {decision.action.op} -> {decision.action.target}")
            elif verdict == "needs_approval":
                st.warning(f"APPROVE: {decision.action.op} -> {decision.action.target}")
            else:
                st.error(f"DENIED: {decision.action.op} ({decision.reason})")

st.subheader("Audit trail")
st.json(pipeline.audit.records)
