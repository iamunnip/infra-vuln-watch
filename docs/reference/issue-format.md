# Issue format

## Title

```text
[severity][score][cve id] - name: summary
```

| Part | Example | Values |
| --- | --- | --- |
| severity | `high` | `critical`, `high`, `medium`, `low`, `none`, `unknown` |
| score | `7.5` | CVSS base score from 0.0 to 10.0, or `n/a` |
| cve id | `cve-2026-115365` | Always small letters |
| name | `openbao` | `name` from the inventory |
| summary | | Up to 120 characters from the CVE description |

[ADR 0008](../../adr/0008-issue-title-format.md) explains this format.

## Description sections

Summary, Affected item, Description, Fix and References. A warning appears at the top when the
result needs a manual check.

## Labels

| Label | Meaning |
| --- | --- |
| `vuln-watch` | Opened by this tool |
| `severity-critical`, `severity-high`, `severity-medium`, `severity-low`, `severity-none`, `severity-unknown` | The severity |
| `needs-review` | NVD did not give enough version data to be sure |

## Changes made to NVD text

- `@` mentions are broken so nobody gets notified.
- `<` is escaped.
- `github.com` links use `redirect.github.com`, which still works when clicked and adds no
  "mentioned this" note to other projects.
