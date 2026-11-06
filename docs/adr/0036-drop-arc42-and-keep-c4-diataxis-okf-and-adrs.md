# 0036. Drop arc42 and keep C4, Diataxis, OKF and ADRs

Date: 2026-11-06

Status: Accepted

## Context

[ADR 0005](0005-organise-docs-with-diataxis-okf-arc42-and-adr.md) chose arc42 for the
architecture description, [ADR 0017](0017-use-c4-views-within-arc42.md) placed C4 views inside
it and [ADR 0018](0018-organise-documentation-under-docs.md) split it into 12 files. For one
small command-line tool, most of those sections repeated other docs. Section 9 only linked to
the ADR list, section 4 listed ADRs, and sections 3, 5 and 7 explained diagrams that live in
`docs/c4/`. Every change had to touch two places to describe one thing.

## Decision

- Remove `docs/arc42/`.
- Keep each C4 diagram and its explanation on one page under `docs/c4/`. The package layout
  and file table move to the component view.
- Add a C4 runtime view at `docs/c4/runtime.md` for the scan sequence, failure handling and
  issue lifecycle diagrams that were in arc42 section 6.
- Move goals, constraints, approach, principles, expected behaviour and risks to the Diataxis
  explanation [Design and risks](../diataxis/explanation/design-and-risks.md).
- Move the glossary to the Diataxis [reference](../diataxis/reference/glossary.md).
- Keep OKF in `knowledge/` and ADRs in `docs/adr/` unchanged.

## Consequences

- There are four documentation standards instead of five, and each fact has one home.
- A diagram and its explanation are reviewed together on one page.
- Readers lose arc42's fixed checklist of sections, so a missing topic is less obvious.
  The documentation map in `docs/README.md` lists what to update for each kind of change.
- Older links to `docs/arc42/` no longer resolve.
