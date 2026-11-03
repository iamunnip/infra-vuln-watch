# 0025. Widen reporter name and status matching

Date: 2026-11-03

Status: Accepted

## Context

An inventory record has one vendor and product name, normally taken from NVD's CPE data. Reporters
write their own `affected` data and often spell names differently, such as
`Apache Software Foundation` for the CPE vendor `apache`, or a Go module path as the product. A CVE
with no analyst data and a different spelling was marked not affected and disappeared without a
trace. Those are the CVEs that the keyword search in [ADR 0002](0002-search-nvd-twice-and-compare-versions-locally.md)
exists to catch.

Reporters also list `unaffected` versions, often a fixed version inside a broad affected range. The
scanner read only `affected` entries, so a fixed version could be reported as affected.

## Decision

- Add an optional `tool.aliases` list of other vendor and product pairs. Aliases apply to both CPE
  and reporter data and do not change finding identity.
- When only reporter data exists, it names other products, and the English description contains
  every word of the tool's keyword as a whole word, return unknown instead of not affected.
- Keep not affected when NVD analyst data lists only other products. Analysts use the same CPE names
  as the inventory, so that result is reliable even if the description mentions the tool.
- A reporter's `unaffected` entry that covers the installed version overrides that reporter data's
  affected ranges. It does not override NVD analyst ranges. An entry that cannot be read clears
  nothing. A wildcard end such as `2.5.*` covers the rest of that branch.

## Consequences

- CVEs that were silently dropped now open a `needs-review` issue, so an existing inventory can
  produce new issues on its next scan.
- A CVE about a related product that names the tool in its text can be a false alarm. Accept it with
  `ignore_cves`, or add an alias if the name is really this tool.
- A fixed version is no longer reported because of a broad affected range.
- A conflict between NVD analysts and the reporter is still reported, which is the safer mistake.
