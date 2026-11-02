from datetime import date

import pytest

from infra_vuln_watch.fix_deadline import get_deadline

OPENED = date(2026, 11, 2)


@pytest.mark.parametrize(
    "severity, days, expected",
    [
        ("critical", 2, "2026-11-04"),
        ("high", 7, "2026-11-09"),
        ("medium", 14, "2026-11-16"),
        ("low", 21, "2026-11-23"),
    ],
)
def test_deadlines(severity, days, expected):
    assert get_deadline(severity, OPENED) == {"days": days, "date": expected}


def test_deadline_crosses_into_the_next_year():
    assert get_deadline("critical", date(2026, 12, 30))["date"] == "2027-01-01"


def test_no_deadline_without_a_score():
    assert get_deadline("unknown", OPENED) is None


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical", "unknown"])
def test_known_exploited_always_gets_the_critical_window(severity):
    assert get_deadline(severity, OPENED, known_exploited=True)["days"] == 2
