"""Decide what an open ticket needs after a scan. Tickets are never closed or reopened here."""

from infra_vuln_watch.clients import github_client
from infra_vuln_watch.domain.version_check import NOT_AFFECTED


def plan_update(record, today, version, score=None, status=None, known_exploited=False, new_title=None):
    """Return the changes for an open ticket, or None when it is already up to date.

    The score, status and exploitation arguments are left out when the CVE was not returned by
    this scan. Only the fix date can then be checked. Labels and the title record what has been
    done, so later scans do not repeat a comment.
    """
    labels = set(record['labels'])
    add, remove, notes = [], [], []
    title = None

    if known_exploited and github_client.KNOWN_EXPLOITED_LABEL not in labels:
        add.append(github_client.KNOWN_EXPLOITED_LABEL)
        notes.append('This CVE is now on the CISA KEV list, so it is known to be exploited. '
                     'Check whether its fix date should move earlier.')

    if score is not None:
        wanted = github_client.severity_label(score['severity'])
        current = [label for label in labels if label.startswith('severity-')]
        severity_changed = bool(current) and wanted not in current
        if severity_changed:
            add.append(wanted)
            remove.extend(current)
        if severity_changed or f"[{score['score']}]" not in record['title']:
            title = new_title
            notes.append(f"NVD now gives this CVE a score of {score['score']} ({score['severity']}). "
                         'The fix date has not changed.')

    resolved = status == NOT_AFFECTED
    if resolved and github_client.RESOLVED_LABEL not in labels:
        add.append(github_client.RESOLVED_LABEL)
        notes.append(f'The scan no longer finds version `{version}` affected. '
                     'Check that the upgrade is deployed, then close this ticket.')
    elif status is not None and not resolved and github_client.RESOLVED_LABEL in labels:
        remove.append(github_client.RESOLVED_LABEL)
        notes.append(f'The scan finds version `{version}` affected again.')

    fix_by = record.get('fix_by')
    if not resolved and fix_by is not None and today > fix_by and github_client.OVERDUE_LABEL not in labels:
        add.append(github_client.OVERDUE_LABEL)
        notes.append(f'The fix date of {fix_by.isoformat()} has passed.')

    if not (add or remove or title or notes):
        return None
    return {'add_labels': add, 'remove_labels': remove, 'title': title, 'comment': '\n\n'.join(notes)}
