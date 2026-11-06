# C4 architecture views

These views describe the current implementation. Each page holds one diagram and the
explanation that goes with it. Design goals, principles and risks are in the
[design explanation](../diataxis/explanation/design-and-risks.md); the reasons for each
choice are in the [decision records](../adr/README.md).

| View | Scope |
| --- | --- |
| [Level 1: system context](01-system-context.md) | People and external systems, and what is out of scope |
| [Level 2: containers](02-containers.md) | Applications and data stores |
| [Level 3: components](03-components.md) | Modules inside the scanner and the package layout |
| [Deployment](deployment.md) | GitHub Actions runner, workflows and external services |
| [Runtime](runtime.md) | Scan order, failure handling and the life of an issue |

## Reading the diagrams

Start with the system context, then containers and components. The runtime view describes
execution order; the deployment view shows hosting.

Diagrams use ordinary Mermaid syntax for GitHub rendering. Static views label element types,
responsibilities and communication. Arrows identify callers or writers and their purpose;
API responses return along the same relationship. A C4 container means an application or data
store, including a batch process; it does not imply Docker. Level 4 is omitted while source
code and tests communicate that detail clearly.

## Keeping the views current

When changing external integrations, update the context and container views. When moving
module responsibilities, update the component view and its file table. When changing
execution order, failure handling or hosting, update the runtime and deployment views and any
affected scenarios in the design explanation. Check diagrams against `src/infra_vuln_watch/`,
workflows and tests before merging.
