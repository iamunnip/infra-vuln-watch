# Documentation

| Directory | Purpose | Start here |
| --- | --- | --- |
| `diataxis/` | User tutorials, how-to guides, reference and explanations | [User documentation](diataxis/README.md) |
| `arc42/` | Architecture goals, constraints, structure, runtime, decisions and risks | [Architecture sections](arc42/README.md) |
| `c4/` | System context, container, component and deployment diagrams | [Architecture views](c4/README.md) |
| `adr/` | History and rationale of architecture decisions | [Decision records](adr/README.md) |

The spelling is `diataxis`, following the documentation framework's name.
C4 diagrams have one home under `c4/`; arc42 sections link to those views and explain them.

The [OKF knowledge bundle](../knowledge/index.md) stays at `knowledge/` for AI agents and
people who need domain facts. Keep its frontmatter and index conventions intact. Instructions
for using the scanner belong in Diataxis; project-specific architecture belongs in arc42 and C4.

## Keeping documentation current

Every code change must update relevant documentation in the same PR. Review `knowledge/`
for each change; update affected facts and policies and the knowledge log, or explain in the
PR why no knowledge update applies. See [AGENTS.md](../AGENTS.md).

Use this map to choose the documentation to update:

| Change | Documentation to review |
| --- | --- |
| External integration | C4 context and container views; arc42 sections 3 and 5 |
| Module responsibility | C4 component view; arc42 section 5 |
| Workflow or hosting | C4 deployment view; arc42 sections 6 to 8 |
| Commands, inventory or issue behaviour | Diataxis reference and affected guides |
| Domain facts or policies | OKF concept files and `knowledge/log.md` |
| Significant architecture decision | New ADR and updated decision index |

Preserve accepted ADR content. In the index, link to later decisions that replace or amend it.

Run `python scripts/check_docs.py` from the repository root after installing the project.
CI runs the same check for local Markdown links, heading anchors and OKF metadata conventions.
Leading `/` links in `knowledge/` resolve from the knowledge bundle root; elsewhere they
resolve from the repository root. Remote URLs and Mermaid rendering are not checked.
The checker handles inline links and reference definitions in Markdown prose; it is not a
complete Markdown parser or full OKF schema validator.
