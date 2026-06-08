"""Correlation and classification behavior."""

from __future__ import annotations

import _bootstrap  # noqa: F401  (side effect: puts src/ on sys.path)
from alertward.alerts import sample_alert_stream
from alertward.triage import correlate


def test_correlation_folds_shared_fingerprint():
    incidents = correlate(sample_alert_stream())
    # The two checkout-api error_rate alerts collapse into one incident.
    checkout = [i for i in incidents if i.service == "checkout-api"]
    assert len(checkout) == 1
    assert set(checkout[0].alert_ids) == {"A-1001", "A-1002"}


def test_sample_stream_yields_four_incidents():
    incidents = correlate(sample_alert_stream())
    assert len(incidents) == 4
    assert {i.service for i in incidents} == {
        "checkout-api",
        "orders-db",
        "ssh",
        "log-pipeline",
    }


def test_incidents_sorted_most_severe_first():
    incidents = correlate(sample_alert_stream())
    # The ssh brute-force alert is critical, so it leads.
    assert incidents[0].service == "ssh"
    assert incidents[0].severity == "critical"
    assert incidents[0].category == "security"


def test_category_mapping():
    incidents = {i.service: i for i in correlate(sample_alert_stream())}
    assert incidents["checkout-api"].category == "availability"
    assert incidents["orders-db"].category == "latency"
    assert incidents["log-pipeline"].category == "capacity"


def test_severity_is_max_of_members():
    incidents = {i.service: i for i in correlate(sample_alert_stream())}
    # Both checkout-api alerts are "high".
    assert incidents["checkout-api"].severity == "high"
