# 0010. Fix deadlines by severity

Date: 2026-11-02

Status: Accepted

## Context

Each issue needs a clear owner and a date to fix it by. The project owner set the number of days
for each severity.

## Decision

- Critical 2 days, high 7 days, medium 14 days, low 21 days. The window for critical is 24 to 48
  hours, and the date uses the 48 hour limit because issues show a date and not a time.
- Count from the day the issue is opened. Counting from the CVE publish date would make older CVEs
  overdue the moment they are reported.
- `unknown` severity has no deadline, unless the CVE is on the CISA KEV list (see ADR 0012).
- A score of 0.0 gets no issue, so it needs no deadline (see ADR 0011).
- Every inventory item must name a `team` and an `owner`.

## Consequences

- Every scored issue shows who is responsible and by when.
- The date is only text in the issue. Nothing warns anyone when it passes.
- Changing the days affects new issues only.
