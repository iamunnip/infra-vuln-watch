# Issue format

## Title

```text
[SEVERITY] [score] [CVE id] Tool - summary
```

| Part | Example | Values |
| --- | --- | --- |
| SEVERITY | `HIGH` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, `UNKNOWN` |
| score | `7.5` | CVSS base score from 0.0 to 10.0, or `n/a` |
| CVE id | `CVE-2026-115365` | The id from NVD |
| Tool | `OpenBao` | `display_name` from the inventory |
| summary | | Up to 120 characters from the CVE description |

[ADR 0009](../../adr/0009-issue-title-and-labels.md) explains this format.

## Description sections

| Section | Holds |
| --- | --- |
| Coloured box | Severity, score, tool, version and a link to the CVE |
| What is the problem? | The full description from NVD |
| How to fix it | The version to upgrade to |
| Details | Tool, owner, severity, attack details, weakness and dates |
| Learn more | Links, with advisories first, and the CVSS vector |

The box colour follows the severity: `CAUTION` for critical and high, `WARNING` for medium, `NOTE`
for low, and `IMPORTANT` when there is no severity. A second warning box appears when the result
needs a manual check.

## Labels

| Label | Meaning |
| --- | --- |
| `vuln-watch` | Opened by this tool |
| `severity-critical`, `severity-high`, `severity-medium`, `severity-low`, `severity-none`, `severity-unknown` | The severity |
| `tool-openbao` | The inventory item. Each tool gets its own label |
| `needs-review` | NVD did not give enough version data to be sure |

The score has no label, because it is in the title and the severity label already groups scores.

## Changes made to NVD text

- `@` mentions are broken so nobody gets notified.
- `<` is escaped.
- `github.com` links use `redirect.github.com`, which still works when clicked and adds no
  "mentioned this" note to other projects.
