# Working in infra-vuln-watch

Start with [README.md](README.md), then the [documentation index](docs/README.md) and
[architecture index](docs/arc42/README.md). Read the relevant source and tests before editing.

## Where information belongs

- `knowledge/`: OKF domain facts for AI agents and people. Preserve YAML frontmatter,
  `index.md` and `log.md` conventions. Leading `/` links resolve from this bundle's root.
  Update `knowledge/log.md` when changing domain content.
- `docs/diataxis/`: user tutorials, how-to guides, reference and explanations.
- `docs/arc42/`: architecture explanations in 12 numbered sections.
- `docs/c4/`: one copy of each context, container, component and deployment diagram.
- `docs/adr/`: historical decisions. Add a new ADR for significant changes and update the
  index with links to replacements; preserve the original accepted decision's content.
- `src/infra_vuln_watch/`: Python CLI implementation; `tests/`: pytest tests.
- `inventory/`: grouped `tool` metadata alongside `config` and either `version` or `deployments`,
  ownership and overrides. OpenBao production/staging entries are illustrative demo data.

## Making changes

Every code change must include a corresponding update under `docs/` in the same PR. Review
`knowledge/` for every code change and update affected domain facts or policies and its
`log.md` when they change. If no knowledge content is affected, state that explicitly in the
PR description; do not invent domain changes merely to touch a file.

Keep changes focused and put modules in their responsibility package:

- `cli/`: argument parsing and command entry points.
- `application/`: scan orchestration and output routing.
- `configuration/`: settings, inventory validation and override resolution.
- `domain/`: stable finding identity, CVE interpretation, version matching and deadline policy.
- `clients/`: external HTTP integrations.
- `persistence/`: local delivery state.
- `reporting/`: finding formatting and sanitisation.

Preserve legacy finding IDs for single-version records. Deployment-scoped IDs include the
stable deployment ID, never the version or owner. Reuse the domain identity helpers for
routing, markers and receipts; do not key multi-deployment routes by product name alone.

Keep only `__init__.py` and `__main__.py` at the package root. Update `pyproject.toml` and
reinstall the editable package when moving a console entry point. Changes to external
integrations, module responsibilities or workflows must update the corresponding C4 view and
arc42 section in the same PR. Keep runtime sequences in arc42 section 6. Update user-facing
reference or guides when commands, inventory or issue behaviour changes.

The scanner's normal mode can write GitHub labels and issues, Jira Cloud tickets and Slack
notifications according to resolved global and tool configuration. Use mocked tests for verification;
`--dry-run` skips every output API call and local receipt write but still calls enabled external
vulnerability APIs. Preserve default safe request intervals and never print webhook URLs or tokens. Do not run a live
reporting scan merely to test a code change.

## Checks

From the repository root, after installing with `pip install -e ".[dev]"`:

```bash
python scripts/check_docs.py
ruff check src tests scripts
mypy
python -m pytest --cov --cov-fail-under=90
```

With the existing virtual environment, use `.venv/bin/python` in place of `python`, and
`.venv/bin/ruff` and `.venv/bin/mypy` for the other tools. The scan installs `requirements.txt`, so
regenerate it when a runtime dependency changes; see the
[command-line reference](docs/diataxis/reference/command-line.md#tests).
The documentation check validates local Markdown links and headings plus repository OKF
metadata conventions. It does not check remote URLs. `tests/test_mermaid.py` parses every Mermaid
diagram with the real parser. That needs Node.js and `npm ci --ignore-scripts` in `scripts/mermaid`.
Without them it skips locally, apart from a semicolon check, and fails in CI.
