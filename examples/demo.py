"""Offline demo: run the guarded triage loop on the synthetic alert stream.

    python examples/demo.py

No API key and no Splunk instance required - the stub planner and the
synthetic alert stream make the whole run deterministic.
"""

from __future__ import annotations

from alertward import (
    ActionGuard,
    AuditLog,
    TriagePipeline,
    default_allowed_services,
    render_report,
    sample_alert_stream,
)


def main() -> None:
    pipeline = TriagePipeline(
        guard=ActionGuard(allowed_services=default_allowed_services()),
        audit=AuditLog(),
    )
    result = pipeline.run(sample_alert_stream())

    print(render_report(result))
    print("Audit step counts:", pipeline.audit.counts())


if __name__ == "__main__":
    main()
