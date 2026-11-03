---
type: Product
title: OpenBao
description: How OpenBao appears in NVD and what to watch for when matching it.
resource: https://github.com/openbao/openbao
tags: [openbao, secrets-management]
sources:
  - id: nvd-api
    resource: https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openbao
    title: Live NVD response for OpenBao, read on 2026-11-02
---

# NVD names

Vendor `openbao`, product `openbao`, recorded under the inventory's `tool` mapping. Tracked in [inventory/openbao.yaml](../../inventory/openbao.yaml).

`tool.repo: openbao/openbao` identifies the upstream GitHub project for release links. It does
not select where findings are delivered; that is controlled by `config.outputs`. GitHub is
the currently supported upstream repository host.

The inventory's optional `config` mapping controls how this scanner handles OpenBao findings;
it does not configure the running OpenBao service. The demo file includes the full tool configuration and multiple deployment records. Each
records its own version, environment, team and owner. Empty deployment overrides inherit tool
settings; empty tool overrides inherit global settings. See the [inventory reference](../../docs/diataxis/reference/inventory-format.md).

# Matching notes

- OpenBao is a fork of HashiCorp Vault. Some CVEs carry an OpenBao CPE while their text only
  talks about Vault, so a keyword search alone misses them.
- Plugins are separate products such as `openbao-plugins` and `aws_plugin`. They do not count
  as `openbao` and would need their own inventory file.
- Security fixes land on more than one release branch, for example 2.6.4 and 2.7.1.
- See [record shapes](/vulnerability-data/nvd-record-shapes.md) for the data formats.
