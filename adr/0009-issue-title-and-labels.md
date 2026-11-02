# 0009. Issue title and labels

Date: 2026-11-02

Status: Accepted

## Context

The small letter title from ADR 0008 was harder to read, and repeated the tool's lowercase id. The
project owner chose a new format and asked for labels that make the issue list easy to filter.

## Decision

Use `[SEVERITY] [score] [CVE id] Tool - summary`, for example:

```text
[LOW] [2.1] [CVE-2026-115369] OpenBao - OpenBao from 2.5.0 before 2.6.2 fails to enforce...
```

Add a `tool-<name>` label beside the severity label. Do not add a label for the exact score.

## Consequences

- Issues can be filtered by tool and by severity.
- Inventory items can set `display_name` for the name people read.
- Exact score labels would add dozens of labels with little value, because the title already shows
  the score and the severity label groups scores.
