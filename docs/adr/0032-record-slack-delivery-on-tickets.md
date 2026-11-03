# 0032. Record Slack delivery on tickets

Date: 2026-11-03

Status: Accepted

## Context

Slack receipts live in a local file that the workflow keeps in an Actions cache. GitHub evicts a cache left
unused for 7 days, and scans run by hand ([ADR 0016](0016-run-the-scan-by-hand.md)), so a quiet week could
resend a notification for every finding. Trackers already hold durable state
([ADR 0004](0004-use-github-issues-as-state.md)), including for closed tickets.

Other stores were worse. A state branch would give a job holding secrets `contents: write`, artifacts
expire too, and a scheduled job to keep the cache alive would undo ADR 0016.

## Decision

After a successful notification, add a `slack-<hash>` label to the finding's tickets. The hash is the first
12 characters of the SHA-256 of the webhook, so each destination has its own label and a public label cannot
reveal the secret.

A finding needs Slack delivery only when it has neither a local receipt nor this label on a ticket in its
route. Each scan also labels tickets whose delivery is recorded only in the local receipt file, so existing
deliveries become durable. `repeat: true` uses neither.

The local receipt file stays, because a Slack-only setup has no tickets, and a tracker can fail after Slack
succeeded.

## Consequences

- With a tracker enabled, losing the cache no longer repeats notifications, including for closed tickets.
- Slack-only setups still depend on the receipt file, and can repeat if it is lost.
- Each ticket gets an extra label, and each label costs one more write. GitHub creates the label when first used.
- Removing the label and losing the receipt allows a repeat. If labelling fails, the scan only warns, because
  the notification was delivered.
- A ticket delivered before this change and a receipt lost before its first scan with this change can still
  repeat once.
- Changing the webhook creates a new destination, which is notified again, as it was with receipts.
