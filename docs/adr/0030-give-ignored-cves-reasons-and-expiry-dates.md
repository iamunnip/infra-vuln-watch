# 0030. Give ignored CVEs reasons and expiry dates

Date: 2026-11-03

Status: Accepted

## Context

`scan.ignore_cves` was a list of strings. An entry stayed in force forever, recorded no reason, and a
mistyped ID matched nothing without any warning. A forgotten entry could hide a real vulnerability.

## Decision

- An entry is still a CVE ID, or a mapping with `id` and an optional `reason` and `expires`. Plain IDs keep
  working.
- An ignore lasts through its `expires` date, and the finding can be reported again after that.
- Every entry must look like a CVE ID, compared without regard to case. Anything else fails validation.
- Each scan prints the ignores for each target, including reasons and expired entries.

## Consequences

- A temporary decision ends without anyone having to remember it, and the log shows what was hidden and why.
- A configuration with an entry that is not a CVE ID now fails before any network request.
- A reason stays optional, so a team that wants one on every entry must check for it in review.
- A valid ID for the wrong CVE still cannot be detected.
