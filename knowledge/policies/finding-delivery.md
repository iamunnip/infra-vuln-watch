---
type: Process
title: Finding delivery and acknowledgement
description: How ticket history, notification receipts and partial delivery failures differ.
tags: [reporting, notifications, deduplication, remediation]
---

# Tickets and notifications

A vulnerability finding identifies an inventory product, a deployment when configured, and one
CVE. A deployment is a specific installation, not just a version number. Several installations
can share an environment name but must have distinct stable IDs. A ticket records remediation
work; a notification draws attention to that work. An acknowledged notification is not evidence
that the vulnerability was fixed, and a closed ticket is not proof that deployed software was
upgraded. Verify remediation using the [fix process](/policies/vulnerability-fix-process.md).

# Independent delivery

A finding may need delivery to multiple trackers or channels. Success in one does not imply
success in another. Track each destination's acknowledgement independently and retry only
pending deliveries. In this project, GitHub Issues and Jira Cloud keep deployment-specific ticket history; Slack
notifications use separate local delivery receipts. Closed tickets remain in reporting history.

# Delivery limitations

Remote acceptance and local acknowledgement are separate events. A timeout or interrupted
process can leave the sender unsure whether delivery succeeded. Lost receipts, delayed tracker
search indexes or concurrent sends can cause repeats. Atomic local writes prevent partial
receipt files but do not provide distributed locking or exactly-once delivery. Failed delivery
must not appear as a successful scan; failure in one destination should not erase successful
work in another.

# Filtering and coverage

Severity filters and ignore lists can suppress findings, including known exploited CVEs.
Disabling unknown results or a vulnerability search reduces coverage. An empty selected result
therefore describes the configured search and filtering policy, not an assurance of security.

See the [configuration reference](../../docs/diataxis/reference/configuration.md) for this
project's settings and [delivery setup](../../docs/diataxis/how-to/configure-delivery.md) for use.

# Scope of remediation

Fixing staging does not fix production. Version matching, ownership and remediation deadlines
must be evaluated for each installation. Keep a deployment ID stable when changing its version
or owner. Legacy unscoped findings cannot be automatically assigned to environments; review
and reconcile them when migrating inventory. A CVE affecting two deployments can legitimately
produce two remediation tickets in the same tracker.
