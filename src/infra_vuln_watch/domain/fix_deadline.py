"""Work out how long the team has to fix a CVE."""

from datetime import timedelta

from infra_vuln_watch.configuration.config import merge_config

def get_deadline(severity, opened_on, known_exploited=False, config=None):
    """Return {"days", "date"} for a severity, or None if it has no deadline."""
    # Attacks are already happening, so the score no longer decides how long we have.
    policy = merge_config({}, config if config is not None else {})["fix_days"]
    days = policy["known_exploited"] if known_exploited else policy.get(severity)
    if days is None:
        return None
    return {"days": days, "date": (opened_on + timedelta(days=days)).isoformat()}
