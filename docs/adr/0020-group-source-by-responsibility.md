# 0020. Group source modules by responsibility

Date: 2026-11-03

Status: Accepted

## Context

[ADR 0019](0019-layer-source-and-configure-scans-and-delivery.md) separated clients and reporting,
but CLI, scanning, policy, configuration and state still lived together at the package root.
The expanded integrations make these responsibilities useful navigation boundaries.

## Decision

Keep `__init__.py` and `__main__.py` at the root of `src/infra_vuln_watch/`. Group implementation
modules into `cli/`, `application/`, `configuration/`, `domain/`, `clients/`, `persistence/` and
`reporting/`. Move output routing into application orchestration and CVE interpretation into
the shared domain package. Use explicit imports from the implementation modules.

Update the console entry point to `infra_vuln_watch.cli.main:main`. The module command delegates
to the same function. Preserve CLI options and runtime behaviour. Update tests and architecture
views to match the new paths; preserve previous ADRs as historical descriptions.

## Consequences

Modules have explicit responsibility boundaries and new files have predictable homes.
There are additional package directories, including some with one implementation module.
Internal imports change and existing installations need refreshing to regenerate console scripts.
The refactor changes no vulnerability-domain facts, configuration schema or remediation policy,
so no domain knowledge content requires changing.
