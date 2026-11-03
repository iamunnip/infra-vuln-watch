# 0028. Update open tickets on each scan

Date: 2026-11-03

Status: Accepted

## Context

A ticket was written once and never changed. The risks section accepted three results of that: a CVE
joining the KEV list after its ticket opened, a fix date passing unnoticed, and a stale score in the
title. An upgraded deployment also gave no sign that its open tickets could be closed.

[ADR 0013](0013-how-a-vulnerability-gets-fixed.md) keeps closing a ticket as a human decision, and that
must not change.

## Decision

On each normal scan, for each open GitHub issue or Jira ticket belonging to a scanned target:

- Add `known-exploited` with a comment when the CVE has joined the KEV list.
- Add `overdue` with a comment once the fix date in the ticket has passed. This also runs when NVD no
  longer returns the CVE.
- Update the title and severity label with a comment when the score changes.
- Add `no-longer-affected` with a comment when the installed version no longer matches, and remove it
  with a comment if the version matches again. Only an explicit not affected result counts, so a filter
  or a missing search result never marks a ticket as resolved.

Tickets are never closed or reopened. Closed tickets and CVEs in `ignore_cves` are left alone. Labels
and the title record what has been done, so a comment is not repeated. `scan.update_existing` turns this
off, and dry runs make no changes.

## Consequences

- The three accepted risks are handled without adding a state store, because the trackers hold the state.
- A scan writes to existing tickets, and those comments notify people watching them.
- Existing tickets are updated too, so the first scan after this change can add labels and comments.
- The fix date is read from the ticket's own summary. Someone who removes that line loses `overdue`.
- If a comment succeeds and the label fails, the next scan repeats the comment. This is safer than losing
  the notice.
- Joining the KEV list does not move the fix date. The comment asks someone to review it.
- Slack is not notified about updates.
