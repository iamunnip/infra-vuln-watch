# 11. Risks and technical debt

| Risk | Impact | Response |
| --- | --- | --- |
| NVD data arrives late or incomplete | Late alerts | Keyword search and unknown results reduce this. A second source can be added later |
| Legacy inventory is converted to deployments | New scoped findings may duplicate earlier unscoped tickets | Reconcile old tickets manually; IDs are not inferred |
| Inventory version goes stale | Wrong results | The fix process updates it with each upgrade. Automatic detection is not built |
| A fix date passes unnoticed | Late fixes | Accepted for now. An `overdue` label could be added later |
| Nobody runs the scan | New CVEs go unnoticed | Accepted, because the scan runs by hand. The schedule can come back ([ADR 0016](../adr/0016-run-the-scan-by-hand.md)) |
| A CVE joins the KEV list after its issue opened | Urgency is missed | Accepted for now. The issue says its risk results can change |
| Requests grow with the inventory, up to 2 searches per distinct product/search configuration per scan | Slow scans or rate limiting past about 100 tools | Add an API key first, then revisit [ADR 0014](../adr/0014-keep-full-product-searches.md) |
| Slack cache is evicted or receipts are lost | Repeat notifications | Persist receipts; caches are best effort, not a durable delivery guarantee |
| Jira search indexing lags or independent scans overlap | Duplicate tickets | Workflow concurrency reduces overlap; inspect ambiguous writes before retrying |
| Filters or disabled sources reduce coverage | Important findings can be missed | Defaults retain broad searches and unknown findings; review overrides |
| Wrong vendor or product name in the inventory | Missed CVEs | The how-to guide shows how to look up names |
| A scored issue is not updated if NVD changes the score | Stale title | Accepted for simplicity. The NVD link shows the current score |

[Architecture index](README.md)
