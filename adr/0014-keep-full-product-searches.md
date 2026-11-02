# 0014. Keep full product searches instead of date filtered ones

Date: 2026-11-02

Status: Accepted

## Context

NVD recommends retrieving data incrementally with `lastModStartDate` and `lastModEndDate`, rather
than repeatedly downloading the entire dataset. That guidance is written for systems that keep a
local copy of NVD, and it asks them to resume from the last record they received.

This tool keeps no local copy and no state (ADR 0004). It never downloads the entire dataset: each
scan asks for one product at a time, which is 2 requests per tool.

We tested the date filters against live data for OpenBao on 2026-11-02:

| Search | CVEs returned |
| --- | --- |
| Keyword, no date filter | 44 |
| Keyword, modified in the last 120 days | 30 |
| Keyword, modified in the last 30 days | 17 |
| Keyword, modified in the last 7 days | 6 |
| Keyword, range of 121 days | Rejected: `Date range cannot exceed 120 days` |

## Decision

Keep the full product searches for now. Do not add date filters.

A date filter only shows what changed recently, while this tool needs every CVE that applies to the
version in the inventory. With a 7 day window, these cases would go wrong:

- **A new tool is added:** 38 of the 44 OpenBao CVEs would never be seen.
- **A version changes:** older CVEs that affect the new version would be missed.
- **The gap between scans is longer than the window:** scans run by hand (ADR 0016), so a gap can be
  any length. CVEs changed during that gap would be missed for good, with no error.

Staying inside the rate limits is handled separately, by waiting between requests.

## Consequences

- A scan stays simple and cannot miss older CVEs, and it needs no saved state.
- Request use grows with the inventory: 2 requests per tool per scan.

  | Tools | Requests per scan | Time with no key | Time with a key |
  | --- | --- | --- | --- |
  | 1 | 2 | 13 seconds | 1 second |
  | 50 | 100 | 11 minutes | 1 minute |
  | 100 | 200 | 22 minutes | 2 minutes |

- Look at this again if the inventory passes about 100 tools, or if NVD starts limiting this tool.
  The likely design then is date filtered scans, plus a regular full scan and a full scan for any
  tool whose inventory entry changed.
