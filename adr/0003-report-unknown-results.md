# 0003. Report results we cannot confirm

Date: 2026-11-02

Status: Accepted

## Context

Some CVEs have no version data, or use text we cannot read such as `2.x`. We must choose
between staying quiet and possibly raising a false alarm.

## Decision

Open an issue with the `needs-review` label and a warning that asks a human to check.

## Consequences

- We do not hide a real vulnerability because its data is incomplete.
- Some issues will be false alarms, but the label makes them easy to spot and filter.
