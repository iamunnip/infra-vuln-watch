# 0021. Track deployments independently

Date: 2026-11-03

Status: Accepted

## Context

One product may run at different versions in several environments or clusters. Product/CVE
identity alone lets one environment's ticket suppress another's, and a single owner and version
cannot describe separate installations. Teams also need the complete tool configuration visible
in their inventory and finer overrides for individual deployments.

## Decision

Allow a tool document to contain a non-empty `deployments` list instead of top-level `version`.
Each entry requires a stable ID and quoted version, with environment defaulting to ID. Team
and owner may be inherited from the tool or overridden for each deployment. Shared vendor,
product, repository, keyword and display name remain at the product level.

Resolve built-in defaults, global config, tool config and deployment config in that order.
Merge the partial inventory layers before injecting defaults; nested mappings merge and lists
replace. Every supported setting is available at tool and deployment levels. The OpenBao demo
file includes the full settings from root config.yaml and two illustrative environment records.
Explicit tool values pin settings until removed or changed.

Expand inventory into independent scan targets. Use `tool/deployment-id` for route keys and
`tool/deployment-id/CVE` for tracker markers and Slack receipts. Include scope, version and
ownership in finding presentation, plus a deployment label on tickets. Reuse NVD candidate
records in memory when vendor, product, keyword and NVD settings are identical; version
matching and filtering remain specific to each target.

Single-version files retain their prior schema and `tool/CVE` identity. Do not automatically
assign legacy unscoped tickets to deployments. Keep deployment IDs stable across upgrades.

## Consequences

Findings, ownership, deadlines and output destinations can differ by installation without
suppressing other environments. A product can have multiple deployments in the same environment
with different IDs. More installations may legitimately generate more tickets.

Converting a legacy file or renaming an ID creates new identities. Old tickets and receipts
are not migrated or closed; maintainers must reconcile them. The demo production/staging records
are illustrative, not claims about deployed systems or secure-version recommendations.
