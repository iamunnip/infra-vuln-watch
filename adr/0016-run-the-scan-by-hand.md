# 0016. Run the scan by hand

Date: 2026-11-02

Status: Accepted

## Context

The scan ran on a schedule twice a day (ADR 0007). The project owner wants it to run only when
started by hand.

## Decision

Remove the schedule and keep `workflow_dispatch`. Rename the workflow from `daily-scan` to `scan`,
because it no longer runs daily.

## Consequences

- Nothing runs, and no NVD requests are made, unless someone starts the scan.
- A new CVE is only found at the next manual run, so it can go unnoticed until then.
- GitHub cannot turn off the workflow for being idle, because that only affects schedules.
- Full product searches matter more, because the gap between runs can be any length (ADR 0014).
- The schedule can come back by adding two lines to the workflow.
