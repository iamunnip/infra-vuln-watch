---
type: Policy
title: Fix windows
description: How long a team has to fix a vulnerability, based on its CVSS severity.
tags: [policy, severity, deadlines]
---

# Default windows

| Severity | CVSS score | Fix window |
| --- | --- | --- |
| Critical | 9.0 to 10.0 | 24 to 48 hours |
| High | 7.0 to 8.9 | 7 days |
| Medium | 4.0 to 6.9 | 14 days |
| Low | 0.1 to 3.9 | 21 days |

# Notes

- The window starts when the issue opens, not when the CVE was published.
- Issues show a date and not a time, so critical uses the 48 hour limit.
- By default a CVE on the CISA KEV list gets a separate 2 day window, whatever its score. See
  [CVSS, EPSS and KEV](../vulnerability-data/cvss-epss-kev.md).
- By default, otherwise a CVE with no score has no window, and a score of 0.0 gets no issue.

# Policy overrides

The table describes defaults rather than universal deadlines. Global `config.yaml` settings
can be overridden for each inventory tool under `config.fix_days`. Overrides merge per
severity. Known exploitation uses its own `known_exploited` value, independently of `critical`.
Deadlines count calendar days from the UTC issue-open date, and changes affect new issues only.
A missed deadline should be visible on the ticket, so scans label open tickets as `overdue`.
Unscored CVEs can be given an `unknown` deadline; `null` keeps no deadline. See the
[configuration reference](../../docs/diataxis/reference/configuration.md) for the supported schema.
