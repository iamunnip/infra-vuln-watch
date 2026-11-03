# 0027. Lock scan dependencies and add quality checks

Date: 2026-11-03

Status: Accepted

## Context

The scan job holds an issue-writing token and the NVD, Jira and Slack secrets. `pip install .` pinned
direct dependencies only, so transitive packages and the build backend resolved to whatever was
newest. Continuous integration ran the tests and the documentation check, but no lint, type or
coverage checks.

## Decision

- Generate `requirements.txt` with hashes for every runtime package and setuptools, using pip-compile
  from `pyproject.toml`.
- The scan workflow installs it with `--require-hashes`, then installs the project with `--no-deps`
  and `--no-build-isolation` so nothing else is downloaded. A test checks that the lockfile matches
  the declared dependencies.
- The tests workflow also runs ruff, mypy over `src` with `check_untyped_defs`, and pytest with branch
  coverage and a 90% minimum. Development tools are pinned in the `dev` extra.
- Add `SECURITY.md` for private reports of bugs in this tool.

## Consequences

- A changed or newly published dependency cannot reach a job that holds secrets without a reviewed
  change to the lockfile.
- A dependency update has to change both `pyproject.toml` and `requirements.txt`. Dependabot watches
  both, and the lockfile test fails when they disagree.
- The tests workflow still installs from `pyproject.toml`, so it may resolve newer transitive packages
  than the scan uses. It holds no secrets, and this gives early warning of incompatible updates.
- Ruff uses a small rule set, so the checks catch real mistakes without forcing a restyle.
