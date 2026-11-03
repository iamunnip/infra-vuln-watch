# 0024. Abbreviate production in titles

Date: 2026-11-03

Status: Accepted

## Context

The environment-first format from [ADR 0023](0023-prioritise-environment-in-finding-titles.md)
shows PRODUCTION in compact finding titles. A shorter PROD label leaves more room for the
score, CVE and explanation.

## Decision

Display the environment value `production` as `PROD` in the shared title formatter, ignoring
case. Keep uppercasing other environment names. Preserve distinct deployment suffixes.
Do not change inventory environment values, stable deployment IDs, detail tables, labels or
finding markers. All destinations use the same shared title.

## Consequences

New finding titles and previews use PROD consistently across GitHub, Jira Cloud and Slack.
Deduplication and deployment selection are unchanged. Existing issue titles require an
explicit update; ordinary scans still do not rename earlier tickets.
