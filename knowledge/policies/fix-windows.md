---
type: Policy
title: Fix windows
description: How long a team has to fix a vulnerability, based on its CVSS severity.
tags: [policy, severity, deadlines]
---

# Windows

| Severity | CVSS score | Fix window |
| --- | --- | --- |
| Critical | 9.0 to 10.0 | 24 to 48 hours |
| High | 7.0 to 8.9 | 7 days |
| Medium | 4.0 to 6.9 | 14 days |
| Low | 0.1 to 3.9 | 21 days |

# Notes

- The window starts when the issue opens, not when the CVE was published.
- Issues show a date and not a time, so critical uses the 48 hour limit.
- A CVE on the CISA KEV list always gets the critical window, whatever its score. See
  [CVSS, EPSS and KEV](/vulnerability-data/cvss-epss-kev.md).
- Otherwise a CVE with no score has no window, and a score of 0.0 gets no issue.
