# 0022. Group inventory product metadata

Date: 2026-11-03

Status: Accepted

## Context

Required product identity and lookup fields were mixed with configuration and deployments
at the root of an inventory document. The product fields remain necessary, but need a clear
section alongside the other inventory responsibilities.

## Decision

Group shared product fields under `tool:` and retain sibling `config:` and `deployments:`
sections. For a single-version grouped record, retain `version` at the root. Normalise grouped
metadata into the existing internal representation before validation and deployment expansion.
Continue accepting legacy flat files, but reject files mixing flat and grouped metadata or
unknown grouped sections. Keep stable product and deployment finding identities unchanged.

## Consequences

Inventory documents have three clear sections without duplicating product identity in each
deployment. Existing records remain compatible. Moving metadata under `tool` does not create
new reporting identities or change version matching and configuration precedence.
