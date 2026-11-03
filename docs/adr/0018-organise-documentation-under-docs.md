# 0018. Organise documentation under docs

Date: 2026-11-03

Status: Accepted

## Context

Human documentation was spread between root-level `adr/`, `arc42/` and `docs/`. The architecture
was one long file. C4 views need a clear home without maintaining duplicate diagrams.
The OKF domain knowledge bundle serves AI agents and must retain its conventions.

## Decision

Update the directory choices in [ADR 0005](0005-organise-docs-with-diataxis-okf-arc42-and-adr.md)
and the diagram location in [ADR 0017](0017-use-c4-views-within-arc42.md):

- Keep `knowledge/` at the root for the OKF bundle; preserve its structure and metadata.
- Put user documentation under `docs/diataxis/`.
- Put architecture decision records under `docs/adr/`, preserving their historical content.
- Split arc42 into 12 numbered Markdown files with an index under `docs/arc42/`.
- Store static C4 diagrams and the supporting deployment diagram under `docs/c4/`.
  Link them from arc42 sections 3, 5 and 7; keep their architectural explanation in arc42.
- Keep runtime sequence and issue lifecycle diagrams in arc42 section 6.
- Use `docs/README.md` as the human documentation entry point.

## Consequences

Each type of documentation has a visible home. Diagrams are maintained once and architecture
sections can be reviewed separately. Moves require link updates; older external links to the
previous paths may no longer resolve. No extra documentation generator is required.
