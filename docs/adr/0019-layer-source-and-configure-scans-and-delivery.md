# 0019. Layer source modules and configure scans and delivery

Date: 2026-11-03

Status: Accepted

## Context

The flat package mixes CLI parsing, scan orchestration, HTTP clients and issue presentation.
Deadlines and GitHub-only delivery are hard-coded. Teams need global defaults with per-tool
choices for scanning, sources, GitHub Issues, Jira Cloud tickets and Slack notifications.

## Decision

Keep the Python src layout from [ADR 0006](0006-use-the-python-src-layout.md). Put HTTP clients
in `clients/`, presentation and routing in `reporting/`, and separate `main.py` argument parsing
from `scanner.py` execution. Keep matching, inventory, configuration, state and deadlines as
small modules. The CLI remains the supported entry point; moved internal imports are updated.

Resolve built-in defaults, optional global `config.yaml` (or explicit `--config` path), then
per-tool `config` overrides. Merge mappings recursively and replace lists. Validate every
resolved tool before networking. Reject unknown settings and invalid types. Secrets remain
in environment variables referenced by name, rather than in YAML.

Extend the deadlines in [ADR 0010](0010-fix-deadlines-by-severity.md) with per-severity policy
and an independent known exploitation window. Make scan filters, optional enrichment, NVD
search selection, request settings and destination routing configurable. Keep safe minimum
NVD intervals and delivery pacing. Preserve broad coverage and GitHub-only delivery by default.

Extend the GitHub-only state decision in [ADR 0004](0004-use-github-issues-as-state.md): each
enabled tracker reads its own marker history, including closed tickets. GitHub and Jira Cloud
can operate independently or together. Jira uses REST v3 and plain-text ADF descriptions with
the same finding details. Required identity markers and tracker labels are not configurable.

Slack incoming webhooks are independently optional and use plain-text blocks. Atomic local
receipts, keyed by destination hash and finding identity, deduplicate successful deliveries.
The supplied workflow caches the default receipt directory between runs on the same branch,
including after partial failures. No webhook secrets are persisted. Repeat mode bypasses receipts.

During reporting, attempt destinations independently and fail the run if any delivery fails.
Do not automatically retry writes after ambiguous network errors. Existing tickets remain
immutable. Dry runs preview all selected destinations without output calls or state writes.

## Consequences

Teams can change scan and routing policy without editing source. Each destination has its own
history, so a GitHub success cannot suppress a missing Jira ticket or failed Slack delivery.
The larger configuration surface requires documented schema, inheritance tests and mocked
integration tests. GitHub workflow secrets must be mapped for enabled destinations.

Slack receipts require persistence and serial execution. Cache eviction, process interruption
after remote acceptance, Jira indexing delays or concurrent executions can produce duplicates;
this is not an exactly-once delivery system. The workflow serialises its own scans, not local
processes. Additional Jira required fields must be supplied in the shape its create API expects.

Every code change must update docs and review knowledge impacts, as specified in root AGENTS.md.
