"""Work out how long the team has to fix a CVE."""

from datetime import date, timedelta
import re

from infra_vuln_watch.configuration.config import merge_config

# The summary at the top of a ticket holds the first "Fix by". CVE text comes after it, so only
# that first one is read: later text cannot supply a date for a finding with no deadline.
FIX_BY_LABEL = re.compile(r'Fix by:\**\s*')
ISO_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')


def read_fix_date(text):
    """Return the fix date from a ticket's text, or None if it has no deadline."""
    label = FIX_BY_LABEL.search(text)
    found = ISO_DATE.match(text, label.end()) if label else None
    try:
        return date.fromisoformat(found[0]) if found else None
    except ValueError:
        return None


def get_deadline(severity, opened_on, known_exploited=False, config=None):
    """Return {"days", "date"} for a severity, or None if it has no deadline."""
    # Attacks are already happening, so the score no longer decides how long we have.
    policy = merge_config({}, config if config is not None else {})["fix_days"]
    days = policy["known_exploited"] if known_exploited else policy.get(severity)
    if days is None:
        return None
    return {"days": days, "date": (opened_on + timedelta(days=days)).isoformat()}
