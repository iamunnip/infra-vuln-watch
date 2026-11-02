# 0008. Issue title format

Date: 2026-11-02

Status: Replaced by 0009

## Context

The issue list should show how serious each CVE is at a glance. The project owner chose the order
of the fields in the title.

## Decision

Use `[severity][score][cve id] - name: summary`, for example:

```text
[high][7.5][cve-2026-71543] - openbao: Prior to 2.6.0, templated ACL, PKI, and SSH policies...
```

The installed version goes in the issue description and not in the title.

## Consequences

- The severity and score are the first things a reader sees.
- `name` tells tools apart when the inventory has more than one.
- Titles are not updated if NVD changes a score later (see ADR 0004).
