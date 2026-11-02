# infra-vuln-watch

[![tests](https://github.com/iamunnip/infra-vuln-watch/actions/workflows/tests.yml/badge.svg)](https://github.com/iamunnip/infra-vuln-watch/actions/workflows/tests.yml)

CVE scan of infrastructure inventory.

When you start it, a GitHub Action checks each tool in `inventory/` against the
[National Vulnerability Database](https://nvd.nist.gov/) (NVD). When the installed version
is affected, it opens an issue in this repo:

```text
[LOW] [2.1] [CVE-2026-115363] OpenBao - OpenBao 2.2.0 before 2.6.4 ... contains an information disclosure...
```

The parts are `[SEVERITY] [CVSS score] [CVE id] Tool - summary`. The description holds the
full details and the fix.

The inventory uses OpenBao 2.5.5 as a demo. It is kept old on purpose so the tool has real CVEs
to find, and it is not a real deployment.

Each issue also shows:

- **Risk:** CVSS for severity, EPSS for the chance of an attack, and CISA KEV for known attacks.
- **A fix date:** based on severity, from 48 hours for critical to 21 days for low. Known exploited
  CVEs always get 48 hours.
- **Who is responsible:** the team and owner from the inventory.
- **Labels:** `severity-*`, `tool-*`, and `known-exploited` or `needs-review` when they apply.

See the [issue format](docs/reference/issue-format.md) for the full details.

## Why not just ask NVD for my version?

NVD has an exact version lookup, but it depends on analyst data that many recent CVEs do not
have yet. On 2026-11-02, for OpenBao 2.5.5:

| Method | CVEs found |
| --- | --- |
| NVD exact version lookup | 0 |
| This tool | 16, including 1 critical and 2 high |

This tool runs two broader searches and compares versions itself, so it also catches CVEs that
NVD has not analysed. [ADR 0002](adr/0002-search-nvd-twice-and-compare-versions-locally.md) has
the full reasoning.

## How it works

```mermaid
flowchart LR
    start[Run by hand in GitHub Actions] --> scan["infra_vuln_watch"]
    inventory["inventory/*.yaml"] --> scan
    nvd[NVD CVE API] --> scan
    scan --> check{Installed version affected?}
    check -->|No| skip[Nothing to do]
    check -->|Yes or unsure| reported{Already reported?}
    reported -->|Yes| skip
    reported -->|No| issue[Open GitHub issue]
```

## Quick start

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m infra_vuln_watch --dry-run
.venv/bin/python -m pytest
```

`--dry-run` prints what it finds and does not open issues.

## Repo layout

| Path | What it holds |
| --- | --- |
| `inventory/` | One YAML file per tool |
| `src/infra_vuln_watch/` | The Python package, one file per job |
| `tests/` | Unit tests, run with `pytest` |
| `pyproject.toml` | Project settings and dependencies |
| `.github/workflows/` | The scan, started by hand, and the tests |
| [`docs/`](docs/README.md) | User docs, organised with Diataxis |
| [`knowledge/`](knowledge/index.md) | Domain knowledge, as an OKF bundle |
| [`arc42/`](arc42/README.md) | Architecture description |
| [`adr/`](adr/README.md) | Architecture decision records |

## Documentation

Each standard answers a different question, so each kind of content has one clear home
([ADR 0005](adr/0005-organise-docs-with-diataxis-okf-arc42-and-adr.md)).

| Question | Standard | Start here |
| --- | --- | --- |
| How do I use it? | Diataxis | [Your first scan](docs/tutorials/first-scan.md) |
| How is it built? | arc42 | [Architecture](arc42/README.md) |
| Why was it built this way? | ADRs | [Decision list](adr/README.md) |
| What should I know about the domain? | OKF | [Knowledge bundle](knowledge/index.md) |

## Data sources

This product uses data from the NVD API but is not endorsed or certified by the NVD. EPSS scores
come from [FIRST](https://www.first.org/epss/), and known exploited data comes from the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
