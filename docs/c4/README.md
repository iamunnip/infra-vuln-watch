# C4 architecture views

These views describe the current implementation and support the [arc42 description](../arc42/README.md).
The architecture explanations, constraints, runtime scenarios and risks belong in arc42;
this directory holds the diagrams and their scope.

| View | Scope | arc42 section |
| --- | --- | --- |
| [Level 1: system context](01-system-context.md) | People and external systems | [3. Context and scope](../arc42/03-context-and-scope.md) |
| [Level 2: containers](02-containers.md) | Applications and data stores | [5. Building blocks](../arc42/05-building-block-view.md) |
| [Level 3: components](03-components.md) | Modules inside the scanner | [5. Building blocks](../arc42/05-building-block-view.md) |
| [Deployment](deployment.md) | GitHub Actions runner and external services | [7. Deployment](../arc42/07-deployment-view.md) |

The diagrams use Mermaid embedded in Markdown and render on GitHub. Edit each diagram here
and its explanation in the linked arc42 section together. Runtime sequence diagrams stay in
[arc42 section 6](../arc42/06-runtime-view.md). Level 4 is omitted while source code and tests
communicate that detail clearly.
