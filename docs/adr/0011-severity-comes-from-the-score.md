# 0011. Severity comes from the CVSS score

Date: 2026-11-02

Status: Accepted

## Context

The project owner set one severity scale: 0.1 to 3.9 is low, 4.0 to 6.9 is medium, 7.0 to 8.9 is
high and 9.0 to 10.0 is critical, with 0.0 usually skipped. NVD labels do not always follow this,
because CVSS 2 has no critical level.

## Decision

Work out severity from the score, not from the NVD label. Do not open an issue for a score of 0.0.
Still open an issue when a CVE has no score, with the severity `UNKNOWN`.

## Consequences

- Titles, labels and fix deadlines all follow one scale, whatever the CVSS version.
- A CVE with a score of 0.0 is never reported, even if the installed version is affected.
- A CVE with no score is still reported, because no score does not mean no risk.
