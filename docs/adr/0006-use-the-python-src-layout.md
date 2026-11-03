# 0006. Use the Python src layout

Date: 2026-11-02

Status: Accepted

## Context

The Python code began as loose files in `src/`, with requirements files beside them. The project
should follow the recommended Python structure, so that it is familiar to new contributors.

## Decision

Follow the [src layout](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/):

```text
pyproject.toml
src/infra_vuln_watch/
tests/
```

`pyproject.toml` holds the settings and dependencies, and replaces the requirements files.

## Consequences

- The package must be installed before it runs, which is one extra step for beginners.
- Tests run against the installed package, so packaging mistakes show up early.
- Commands run from the top folder of the repo, using `python -m infra_vuln_watch`.
- The default `inventory` path is relative to where the command runs, because an installed
  package does not sit beside the repo files.
