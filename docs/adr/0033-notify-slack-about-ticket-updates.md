# 0033. Notify Slack about ticket updates

Date: 2026-11-03

Status: Accepted

## Context

[ADR 0028](0028-update-open-tickets-on-each-scan.md) added ticket updates but did not notify Slack. A CVE joining
the KEV list, which can change what a team does next, only appeared on the ticket, where people who rely on
the Slack channel might not see it.

## Decision

When a scan updates an open ticket, send one Slack message to that route's channel with the title, the same
text as the ticket comment and a link. `notifications.slack.notify_updates`, on by default, turns this off.

Send it after the ticket changes. Ticket labels and titles already stop an update repeating, so no receipt is
needed. When two trackers receive the same update in one run, Slack is told once.

## Consequences

- Teams see new exploitation, missed fix dates, score changes and possible closures where they already look.
- Channels get more messages, so a first scan that marks many tickets as overdue can be noisy.
- A failed notification fails the run but is not retried, because the ticket has already changed. The ticket
  still holds the update, so the information is not lost.
- If the trackers update in different runs, for example because one was rate limited, Slack is told each time.
