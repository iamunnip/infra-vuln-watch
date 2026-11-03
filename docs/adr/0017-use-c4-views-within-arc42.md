# 0017. Use C4 views within arc42

Date: 2026-11-03

Status: Accepted

## Context

The architecture already follows arc42, but its diagrams mix system context, source modules
and hosting details without explicit levels of abstraction. Readers need to move from the
system's purpose to its runtime boundaries and then to the code that implements them.

## Decision

Keep the 12 arc42 sections as the architecture's home, extending
[ADR 0005](0005-organise-docs-with-diataxis-okf-arc42-and-adr.md) with C4 views:

- System context in section 3.
- Container and component views in section 5.
- Supporting runtime sequences in section 6 and deployment view in section 7.

Use Mermaid flowcharts with explicit types, boundaries, responsibilities and labelled
relationships. They render in GitHub Markdown without a separate diagram build pipeline.
The scanner is one application container; its Python modules are components. Inventory is a
YAML file store. GitHub remains an external platform providing execution and issue history.

Omit level 4 code diagrams while functions and tests communicate those details clearly.
Keep each view in the arc42 document rather than maintaining parallel copies elsewhere.

## Consequences

- Readers can follow consistent levels of detail within the existing documentation structure.
- Diagrams are reviewable alongside source changes and require no additional dependencies.
- Mermaid does not enforce C4 semantics, so reviewers must check boundaries and labels.
- Changes to integrations, modules or workflows require updates to the corresponding views.

References: [C4 diagrams](https://c4model.com/diagrams),
[C4 containers](https://c4model.com/abstractions/container),
[arc42 overview](https://arc42.org/overview/).
