# Architecture of infra-vuln-watch

[arc42](https://arc42.org/overview/) organises the architecture description.
[C4](https://c4model.com/diagrams) supplies its visual views. Each diagram lives once in
[`../c4/`](../c4/README.md) and is linked from the relevant section below.

## Sections

- [1. Introduction and goals](01-introduction-and-goals.md)
- [2. Constraints](02-constraints.md)
- [3. Context and scope](03-context-and-scope.md)
- [4. Solution strategy](04-solution-strategy.md)
- [5. Building block view](05-building-block-view.md)
- [6. Runtime view](06-runtime-view.md)
- [7. Deployment view](07-deployment-view.md)
- [8. Crosscutting concepts](08-crosscutting-concepts.md)
- [9. Architecture decisions](09-architecture-decisions.md)
- [10. Quality requirements](10-quality-requirements.md)
- [11. Risks and technical debt](11-risks-and-technical-debt.md)
- [12. Glossary](12-glossary.md)

## Reading the diagrams

Start with [system context](../c4/01-system-context.md), then
[containers](../c4/02-containers.md) and [components](../c4/03-components.md).
[Runtime sequences](06-runtime-view.md) describe execution order; the
[deployment view](../c4/deployment.md) shows hosting.

Diagrams use ordinary Mermaid syntax for GitHub rendering. Static views label element types,
responsibilities and communication. Arrows identify callers or writers and their purpose;
API responses return along the same relationship. A C4 container means an application or data
store, including a batch process; it does not imply Docker.

Level 4 code diagrams are omitted because functions and tests provide the useful detail.
See [ADR 0017](../adr/0017-use-c4-views-within-arc42.md) and the
[directory organisation decision](../adr/0018-organise-documentation-under-docs.md).

## Maintaining this description


When changing external integrations, update section 3 and the container view. When moving
module responsibilities, update the component view and file table. When changing execution
order, failure handling or hosting, update sections 6–8 and affected quality scenarios.
Record significant decisions in `docs/adr/`; keep tutorials and domain explanations in their existing
homes. Check diagrams against `src/infra_vuln_watch/`, workflows and tests before merging.
