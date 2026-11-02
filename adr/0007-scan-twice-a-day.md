# 0007. Scan twice a day

Date: 2026-11-02

Status: Replaced by 0016

## Context

The first plan was one scan a day at 06:00 IST. The project owner asked for two scans a day
instead, at 12am and 12pm IST.

## Decision

Run the workflow with the cron `30 6,18 * * *`. Cron uses UTC, so 18:30 UTC is 00:00 IST and
06:30 UTC is 12:00 IST.

## Consequences

- A new CVE is reported sooner, usually within 12 hours of appearing in NVD.
- NVD gets twice as many requests, still well inside the rate limit for a small inventory.
- No duplicate issues, because reported CVEs are skipped (see ADR 0004).
- GitHub can start scheduled runs late, so these times are the earliest and not exact.
