"""Correlate raw alerts into incidents and classify them.

Correlation is deterministic: alerts that share a (service, signal) fingerprint
fold into one incident. Severity is the max of the member alerts; category is
derived from the dominant signal. This is intentionally simple and rule-based
so the output is reproducible and the guard's behavior is easy to reason about.
"""

from __future__ import annotations

from .alerts import (
    SEVERITY_RANK,
    Alert,
    Category,
    Incident,
    Severity,
)

_SIGNAL_CATEGORY: dict[str, Category] = {
    "error_rate": "availability",
    "latency": "latency",
    "auth_bruteforce": "security",
    "disk_capacity": "capacity",
    "parse_error": "data_quality",
}


def _category_for(signal: str) -> Category:
    return _SIGNAL_CATEGORY.get(signal, "unknown")


def _max_severity(alerts: list[Alert]) -> Severity:
    return max(alerts, key=lambda a: SEVERITY_RANK[a.raw_severity]).raw_severity


def correlate(alerts: list[Alert]) -> list[Incident]:
    """Group alerts by (service, signal) into incidents, newest grouping last.

    The grouping order follows first-seen order of each fingerprint so the
    incident list is stable across runs (important for prompt-cache stability
    when a real planner is driven over the result).
    """

    order: list[tuple[str, str]] = []
    groups: dict[tuple[str, str], list[Alert]] = {}
    for alert in alerts:
        key = (alert.service, alert.signal)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(alert)

    incidents: list[Incident] = []
    for idx, key in enumerate(order, start=1):
        members = groups[key]
        service, signal = key
        category = _category_for(signal)
        severity = _max_severity(members)
        summary = (
            f"{len(members)} alert(s) on {service} ({signal}); "
            f"max severity {severity}"
        )
        incidents.append(
            Incident(
                incident_id=f"INC-{idx:03d}",
                service=service,
                category=category,
                severity=severity,
                alert_ids=[a.alert_id for a in members],
                summary=summary,
            )
        )

    # Most severe incidents first; ties keep correlation order.
    incidents.sort(key=lambda inc: SEVERITY_RANK[inc.severity], reverse=True)
    return incidents
