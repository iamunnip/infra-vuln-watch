"""Read scan.ignore_cves entries: a CVE ID, or a mapping with a reason and an expiry date."""

from datetime import date, datetime


def expiry_date(value):
    """Return an expiry from YAML as a date. YAML may already have parsed it."""
    if isinstance(value, datetime):
        return value.date()
    return value if isinstance(value, date) else date.fromisoformat(value)


def normalise(entry):
    """Return an entry as a mapping with id, reason and expires keys."""
    if isinstance(entry, str):
        return {'id': entry.upper(), 'reason': None, 'expires': None}
    expires = entry.get('expires')
    return {'id': entry['id'].upper(), 'reason': entry.get('reason'),
            'expires': None if expires is None else expiry_date(expires)}


def is_active(entry, today):
    """An ignore lasts through its expiry date."""
    return entry['expires'] is None or today <= entry['expires']


def is_ignored(cve_id, entries, today):
    return any(item['id'] == cve_id.upper() and is_active(item, today) for item in map(normalise, entries))


def describe(entries, today):
    """Return one log line for each ignore, so that the run shows what was hidden and why."""
    lines = []
    for item in map(normalise, entries):
        if not is_active(item, today):
            lines.append(f"Ignore of {item['id']} expired on {item['expires']}, so it can be reported again")
            continue
        until = f" until {item['expires']}" if item['expires'] else ''
        reason = f": {item['reason']}" if item['reason'] else ''
        lines.append(f"Ignoring {item['id']}{until}{reason}")
    return lines
