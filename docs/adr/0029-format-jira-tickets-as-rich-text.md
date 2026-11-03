# 0029. Format Jira tickets as rich text

Date: 2026-11-03

Status: Accepted

## Context

[ADR 0019](0019-layer-source-and-configure-scans-and-delivery.md) sent the GitHub Markdown to Jira as plain
text in Atlassian Document Format (ADF), to stop CVE text creating mentions or markup. It was safe, but
tables and alert boxes showed up as raw symbols, which made tickets hard to read.

## Decision

Convert the Markdown that `issue_format` writes into ADF panels, headings, tables, lists and text marks.

- Build no mention, media or other active node, and allow links only to `http` and `https` addresses.
- Keep the finding marker as exact plain text. Restore an escaped `<` for reading, except before `!--`,
  so CVE text cannot fake a marker.
- If Jira rejects the formatted ticket with a 400 response, send it again as plain text. A rejected
  request created nothing, so this cannot duplicate a ticket.

## Consequences

- Jira tickets are as readable as GitHub issues, and new tickets differ from older plain text ones.
- The formatter only understands the Markdown this project writes, so a new body format needs matching
  support. Anything else stays plain text.
- Markdown in a CVE description, such as bold text or a link, also renders in Jira, as it already does on
  GitHub.
- ADF has only been tested against a fake Jira that applies its main rules. The plain text fallback covers
  anything the real one rejects.
