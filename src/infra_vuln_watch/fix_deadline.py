"""Work out how long the team has to fix a CVE."""

from datetime import timedelta

# How many days the team has to fix a CVE, counted from the day the issue opens.
# A CVE with no score has the severity "unknown", which has no deadline.
FIX_DAYS = {
    "critical": 2,  # The window is 24 to 48 hours, so the latest date is 2 days.
    "high": 7,
    "medium": 14,
    "low": 21,
}


def get_deadline(severity, opened_on, known_exploited=False):
    """Return {"days", "date"} for a severity, or None if it has no deadline."""
    # Attacks are already happening, so the score no longer decides how long we have.
    days = FIX_DAYS["critical"] if known_exploited else FIX_DAYS.get(severity)
    if days is None:
        return None
    return {"days": days, "date": (opened_on + timedelta(days=days)).isoformat()}
