# Architecture decision records

Each record explains one important decision and why it was made. Records are not edited after
they are accepted. To change a decision, add a new record that replaces the old one. Copy
[the template](template.md) to start a new record.

| Number | Decision | Status |
| --- | --- | --- |
| [0001](0001-use-nvd-as-the-cve-source.md) | Use NVD as the CVE source | Accepted |
| [0002](0002-search-nvd-twice-and-compare-versions-locally.md) | Search NVD twice and compare versions locally | Accepted |
| [0003](0003-report-unknown-results.md) | Report results we cannot confirm | Accepted |
| [0004](0004-use-github-issues-as-state.md) | Use GitHub Issues as the only state | Extended by [0019](0019-layer-source-and-configure-scans-and-delivery.md) |
| [0005](0005-organise-docs-with-diataxis-okf-arc42-and-adr.md) | Organise docs with Diataxis, OKF, arc42 and ADRs | Directory layout amended by [0018](0018-organise-documentation-under-docs.md) |
| [0006](0006-use-the-python-src-layout.md) | Use the Python src layout | Accepted |
| [0007](0007-scan-twice-a-day.md) | Scan twice a day | Replaced by [0016](0016-run-the-scan-by-hand.md) |
| [0008](0008-issue-title-format.md) | Issue title format | Replaced by [0009](0009-issue-title-and-labels.md) |
| [0009](0009-issue-title-and-labels.md) | Issue title and labels | Title format replaced by [0023](0023-prioritise-environment-in-finding-titles.md); labels retained |
| [0010](0010-fix-deadlines-by-severity.md) | Fix deadlines by severity | Configuration amended by [0019](0019-layer-source-and-configure-scans-and-delivery.md) |
| [0011](0011-severity-comes-from-the-score.md) | Severity comes from the CVSS score | Accepted |
| [0012](0012-add-epss-and-cisa-kev.md) | Add EPSS and CISA KEV | Accepted |
| [0013](0013-how-a-vulnerability-gets-fixed.md) | How a vulnerability gets fixed | Accepted |
| [0014](0014-keep-full-product-searches.md) | Keep full product searches instead of date filtered ones | Accepted |
| [0015](0015-read-nvd-and-not-cve-org.md) | Read NVD and not CVE.org | Accepted |
| [0016](0016-run-the-scan-by-hand.md) | Run the scan by hand | Accepted |
| [0017](0017-use-c4-views-within-arc42.md) | Use C4 views within arc42 | Diagram location amended by [0018](0018-organise-documentation-under-docs.md) |
| [0018](0018-organise-documentation-under-docs.md) | Organise documentation under docs | Accepted |
| [0019](0019-layer-source-and-configure-scans-and-delivery.md) | Layer source modules and configure scans and delivery | Severity filter scope amended by [0026](0026-known-exploited-cves-pass-severity-filters.md); Jira description format amended by [0029](0029-format-jira-tickets-as-rich-text.md) |
| [0020](0020-group-source-by-responsibility.md) | Group source modules by responsibility | Accepted |
| [0021](0021-track-deployments-independently.md) | Track deployments independently | Accepted |
| [0022](0022-group-inventory-product-metadata.md) | Group inventory product metadata | Accepted |
| [0023](0023-prioritise-environment-in-finding-titles.md) | Prioritise environment in finding titles | Accepted |
| [0024](0024-abbreviate-production-in-titles.md) | Abbreviate production in titles | Accepted |
| [0025](0025-widen-reporter-name-and-status-matching.md) | Widen reporter name and status matching | Accepted |
| [0026](0026-known-exploited-cves-pass-severity-filters.md) | Known exploited CVEs pass severity filters | Accepted |
| [0027](0027-lock-scan-dependencies-and-add-quality-checks.md) | Lock scan dependencies and add quality checks | Accepted |
| [0028](0028-update-open-tickets-on-each-scan.md) | Update open tickets on each scan | Slack notification amended by [0033](0033-notify-slack-about-ticket-updates.md) |
| [0029](0029-format-jira-tickets-as-rich-text.md) | Format Jira tickets as rich text | Accepted |
| [0030](0030-give-ignored-cves-reasons-and-expiry-dates.md) | Give ignored CVEs reasons and expiry dates | Accepted |
| [0031](0031-respect-rate-limits-on-outputs.md) | Respect rate limits on outputs | Accepted |
| [0032](0032-record-slack-delivery-on-tickets.md) | Record Slack delivery on tickets | Accepted |
| [0033](0033-notify-slack-about-ticket-updates.md) | Notify Slack about ticket updates | Accepted |
