# 0005. Organise docs with Diataxis, OKF, arc42 and ADRs

Date: 2026-11-02

Status: Accepted

## Context

Different readers need different things: how to use the tool, facts about the domain, how it is
built, and why it was built that way.

## Decision

| Directory | Standard | Holds |
| --- | --- | --- |
| `docs/` | Diataxis | Tutorials, how-to guides, reference and explanation |
| `knowledge/` | OKF v0.2 | Domain facts for people and AI agents |
| `arc42/` | arc42 | The architecture overview |
| `adr/` | ADRs | One record for each decision |

## Consequences

- Each kind of content has one clear home.
- There are more places to keep up to date when behaviour changes.
- `knowledge/` must stay valid OKF: every concept needs YAML frontmatter with a `type`, and
  `index.md` and `log.md` are reserved names.
