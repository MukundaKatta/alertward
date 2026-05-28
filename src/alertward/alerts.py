"""Alert and incident domain types plus a deterministic offline alert stream.

In a live deployment the alerts arrive from Splunk (a search export, an alert
action webhook, or the HTTP Event Collector). For the offline demo and the
tests we synthesize a fixed stream so the whole guarded loop is reproducible
with no Splunk instance and no API key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal[
    "availability",
    "latency",
    "security",
    "capacity",
    "data_quality",
    "unknown",
]

SEVERITY_RANK: dict[Severity, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Alert:
    """A single observability/security alert as it lands from the source."""

    alert_id: str
    source: str
    host: str
    service: str
    message: str
    raw_severity: Severity
    fired_at: str
    signal: str

    def to_dict(self) -> dict[str, object]:
        return {
            "alert_id": self.alert_id,
            "source": self.source,
            "host": self.host,
            "service": self.service,
            "message": self.message,
            "raw_severity": self.raw_severity,
            "fired_at": self.fired_at,
            "signal": self.signal,
        }


@dataclass
class Incident:
    """A correlated group of alerts that share a service/host fingerprint."""

    incident_id: str
    service: str
    category: Category
    severity: Severity
    alert_ids: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "service": self.service,
            "category": self.category,
            "severity": self.severity,
            "alert_ids": list(self.alert_ids),
            "summary": self.summary,
        }


def _ts(minute: int) -> str:
    return datetime(2026, 6, 1, 9, minute, 0, tzinfo=timezone.utc).isoformat()


def sample_alert_stream() -> list[Alert]:
    """A fixed synthetic stream covering each category and a noisy duplicate.

    Two of these alerts share a service/signal fingerprint so the correlator
    has something real to fold together; the security alert is the one that
    should drive a non-destructive, approval-gated response.
    """

    return [
        Alert(
            alert_id="A-1001",
            source="splunk:savedsearch",
            host="web-07",
            service="checkout-api",
            message="HTTP 5xx ratio 0.34 over 5m (threshold 0.05)",
            raw_severity="high",
            fired_at=_ts(2),
            signal="error_rate",
        ),
        Alert(
            alert_id="A-1002",
            source="splunk:savedsearch",
            host="web-09",
            service="checkout-api",
            message="HTTP 5xx ratio 0.29 over 5m (threshold 0.05)",
            raw_severity="high",
            fired_at=_ts(3),
            signal="error_rate",
        ),
        Alert(
            alert_id="A-1003",
            source="splunk:itsi",
            host="db-primary",
            service="orders-db",
            message="p99 query latency 4200ms (threshold 800ms)",
            raw_severity="medium",
            fired_at=_ts(4),
            signal="latency",
        ),
        Alert(
            alert_id="A-1004",
            source="splunk:es",
            host="bastion-1",
            service="ssh",
            message="42 failed logins for root from 198.51.100.23 in 60s",
            raw_severity="critical",
            fired_at=_ts(5),
            signal="auth_bruteforce",
        ),
        Alert(
            alert_id="A-1005",
            source="splunk:savedsearch",
            host="ingest-3",
            service="log-pipeline",
            message="disk usage 91% on /var/log (threshold 85%)",
            raw_severity="medium",
            fired_at=_ts(6),
            signal="disk_capacity",
        ),
    ]
