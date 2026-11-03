# 0023. Prioritise environment in finding titles

Date: 2026-11-03

Status: Accepted

## Context

Finding titles placed the environment after the product name. Compact issue lists and
notifications can truncate that context. The same title needs to identify urgency and
installation scope across GitHub, Jira Cloud and Slack without relying on platform styling.

## Decision

Replace the title format from [ADR 0009](0009-issue-title-and-labels.md) with:

```text
[SEVERITY] [ENVIRONMENT/deployment] [score] CVE-id Tool - summary
```

Use uppercase environment names and retain a distinct deployment ID after a slash. Omit that
ID if it matches the environment ignoring case. Omit the whole environment segment for
single-version records. Leave the CVE ID unbracketed and avoid repeating scope after the tool.

Use the shared title for GitHub issue titles, Jira Cloud summaries and Slack plain-text blocks.
Use the escaped title as Slack notification fallback text with Markdown disabled. Brackets are
visual separators, not styling, labels or tracker priority. Keep existing labels and finding
identity markers unchanged; do not automatically rename earlier tickets.

## Consequences

Severity and scope are visible earlier in compact lists. Deployment IDs disambiguate different
installations sharing an environment. Missing scores remain explicit as n/a. Summary and output
length limits still apply. Title formatting tests cover all destinations and Slack escaping.
