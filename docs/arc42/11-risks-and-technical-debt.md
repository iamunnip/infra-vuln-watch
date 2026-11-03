# 11. Risks and technical debt

| Risk | Impact | Response |
| --- | --- | --- |
| NVD data arrives late or incomplete | Late alerts | Keyword search and unknown results reduce this. A second source can be added later |
| Legacy inventory is converted to deployments | New scoped findings may duplicate earlier unscoped tickets | Reconcile old tickets manually; IDs are not inferred |
| Inventory version goes stale | Wrong results | The fix process updates it with each upgrade. Automatic detection is not built |
| A fix date passes unnoticed | Late fixes | Each scan adds an `overdue` label and comment, but only when a scan runs ([ADR 0028](../adr/0028-update-open-tickets-on-each-scan.md)) |
| Nobody runs the scan | New CVEs go unnoticed | Accepted, because the scan runs by hand. The schedule can come back ([ADR 0016](../adr/0016-run-the-scan-by-hand.md)) |
| A CVE joins the KEV list after its issue opened | Urgency is missed | The next scan adds `known-exploited` and a comment. Its fix date is left for a person to review |
| Requests grow with the inventory, up to 2 searches per distinct product/search configuration per scan | Slow scans or rate limiting past about 100 tools | Add an API key first, then revisit [ADR 0014](../adr/0014-keep-full-product-searches.md) |
| Slack cache is evicted or receipts are lost | Repeat notifications | Persist receipts; caches are best effort, not a durable delivery guarantee. GitHub evicts caches unused for 7 days, which manual scans can reach. Accepted for now |
| Jira search indexing lags or independent scans overlap | Duplicate tickets | Workflow concurrency reduces overlap; inspect ambiguous writes before retrying |
| Filters or disabled sources reduce coverage | Important findings can be missed | Severity filters never hide known exploited CVEs. Defaults retain broad searches and unknown findings; review overrides |
| Wrong vendor or product name in the inventory | Missed CVEs | The how-to guide shows how to look up names. A description that names the tool still opens a review issue when no analyst data exists |
| Reporter and CPE names differ | Review issues instead of exact answers, and some false alarms | Add `tool.aliases`, or use `ignore_cves` for an unrelated product ([ADR 0025](../adr/0025-widen-reporter-name-and-status-matching.md)) |
| Lockfile falls behind `pyproject.toml` | Scan runs other versions than declared | A test fails when they disagree ([ADR 0027](../adr/0027-lock-scan-dependencies-and-add-quality-checks.md)) |
| Scans write to existing tickets | Comments notify watchers, and a failed label can repeat a comment | Changes are made only when facts change, and `scan.update_existing` turns them off |
| Fake services differ from the real ones | A delivery bug passes the mock tests | Mock tests apply each service's main rules, and Jira falls back to plain text. Check the first real run |
| A large backlog meets rate limits | Delivery takes several scans | The scan stops sending to that destination and fails, and the next one catches up ([ADR 0031](../adr/0031-respect-rate-limits-on-outputs.md)) |

[Architecture index](README.md)
