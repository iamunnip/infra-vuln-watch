# 4. Solution strategy

- Run the scan by hand ([ADR 0016](../adr/0016-run-the-scan-by-hand.md)). GitHub Issues and/or Jira Cloud remember reported tickets
  ([ADR 0004](../adr/0004-use-github-issues-as-state.md), extended by
  [ADR 0019](../adr/0019-layer-source-and-configure-scans-and-delivery.md)). Optional Slack
  receipts and a label on each ticket track notification delivery independently
  ([ADR 0032](../adr/0032-record-slack-delivery-on-tickets.md)).
- Keep open tickets current when their facts change, but leave closing them to people
  ([ADR 0028](../adr/0028-update-open-tickets-on-each-scan.md)).
- Search NVD twice and compare versions locally
  ([ADR 0002](../adr/0002-search-nvd-twice-and-compare-versions-locally.md)).
- When unsure, report and ask a human ([ADR 0003](../adr/0003-report-unknown-results.md)).
- People do the fixing, through a pull request ([ADR 0013](../adr/0013-how-a-vulnerability-gets-fixed.md)).

[Architecture index](README.md)

- Resolve defaults, global YAML and tool overrides before networking. Ticket and notification
  destinations are independently selectable. A delivery failure fails the run while other
  destinations and findings continue. Optional enrichment failures remain warnings.
