# 0004. Use GitHub Issues as the only state

Date: 2026-11-02

Status: Accepted

## Context

A daily job must remember what it already reported. A state file would need commits or a
database.

## Decision

Put a hidden `vuln-watch-id` comment in each issue, and read it back at the start of each run,
including from closed issues. Only trust issues with the `vuln-watch` label, because in a public
repo anyone can open an issue but only people with write access can label it.

## Consequences

- There is no database, and the workflow does not need write access to the code.
- Closing an issue is a permanent decision for that tool and CVE.
- Titles are not updated when NVD changes a score later.
- Removing the label or marker from an issue causes a duplicate on the next run.
