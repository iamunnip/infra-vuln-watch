# Documentation

| Directory | Purpose | Start here |
| --- | --- | --- |
| `diataxis/` | User tutorials, how-to guides, reference and explanations | [User documentation](diataxis/README.md) |
| `c4/` | Architecture diagrams with their explanations: context, containers, components, deployment and runtime | [Architecture views](c4/README.md) |
| `adr/` | History and rationale of architecture decisions | [Decision records](adr/README.md) |

The spelling is `diataxis`, following the documentation framework's name.
Each C4 diagram and its explanation share one page under `c4/`. Design goals, principles and
risks are a Diataxis explanation.

The [OKF knowledge bundle](../knowledge/index.md) stays at `knowledge/` for AI agents and
people who need domain facts. Keep its frontmatter and index conventions intact. Instructions
for using the scanner belong in Diataxis; project-specific architecture belongs in C4.

## Keeping documentation current

Every code change must update relevant documentation in the same PR. Review `knowledge/`
for each change; update affected facts and policies and the knowledge log, or explain in the
PR why no knowledge update applies. See [AGENTS.md](../AGENTS.md).

Use this map to choose the documentation to update:

| Change | Documentation to review |
| --- | --- |
| External integration | C4 context and container views |
| Module responsibility | C4 component view |
| Workflow or hosting | C4 deployment and runtime views |
| Commands, inventory or issue behaviour | Diataxis reference and affected guides |
| Goals, principles, expected behaviour or risks | [Design and risks](diataxis/explanation/design-and-risks.md) |
| Domain facts or policies | OKF concept files and `knowledge/log.md` |
| Significant architecture decision | New ADR and updated decision index |

Preserve accepted ADR content. In the index, link to later decisions that replace or amend it.

Run `python scripts/check_docs.py` from the repository root after installing the project.
CI runs the same check for local Markdown links, heading anchors and OKF metadata conventions.
Links are checked the way GitHub resolves them, so a leading `/` means the repository root. Links in
`knowledge/` must be relative, because a leading `/` link there is not found on GitHub. Files named in plain
text and this repository's own GitHub URLs must exist too. Other remote URLs are not checked, and
`tests/test_mermaid.py` checks Mermaid syntax.
The checker handles inline links and reference definitions in Markdown prose; it is not a
complete Markdown parser or full OKF schema validator.
