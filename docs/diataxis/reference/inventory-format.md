# Inventory format

Each product has one `.yaml` or `.yml` file in `inventory/`. Use a single `version` for a simple record,
or `deployments` for different versions, environments, clusters or owners.

## Root sections

| Key | Purpose |
| --- | --- |
| `tool` | Shared product identity, GitHub repository and NVD lookup names; optional display name and default ownership |
| `config` | Tool-wide overrides of global settings; credentials are referenced by environment variable name |
| `deployments` | Independently tracked installations with versions, environments, ownership and optional overrides |

These sections match the explanations above each root key in the OpenBao sample. For a
single-version record, use root `version` instead of `deployments`.

`tool.repo` currently accepts a GitHub `owner/repository` string only. It identifies the
upstream project used for repository and release links, independently of the destinations
under `config.outputs`. GitLab repositories and a repository `type`/`url` mapping are not
implemented.

## Product fields

Group shared product metadata under `tool:`. Keep `config:` and `deployments:` as sibling
sections. The loader normalises this grouping internally; finding identities do not change.
Do not repeat product metadata at the root when `tool:` is present.

| Field | Required | Example | Meaning |
| --- | --- | --- | --- |
| `tool.name` | Yes | `openbao` | Stable product name; unique across files; no whitespace |
| `tool.repo` | Yes | `openbao/openbao` | Upstream GitHub repository used for the releases link |
| `tool.vendor` | Yes | `openbao` | NVD vendor name |
| `tool.product` | Yes | `openbao` | NVD product name |
| `tool.display_name` | No | `OpenBao` | Human-readable product name; defaults to `name` |
| `tool.keyword` | No | `openbao` | NVD keyword search; defaults to `name` |
| `tool.aliases` | No | See below | Other vendor and product names used for this tool in CVE data |
| `tool.team` | See below | `sre` | Default responsible team; can be overridden per deployment |
| `tool.owner` | See below | `iamunnip` | Default responsible owner; can be overridden per deployment |
| `version` | Single-version records | `"2.5.5"` | Installed version; mutually exclusive with `deployments` |
| `deployments` | Multi-deployment records | See example | Non-empty list of independently scanned installations |
| `config` | No | `fix_days: {high: 3}` | Any supported global setting, overridden for this product |

Every resolved installation must have a quoted valid version and non-empty string `team`
and `owner`. Product-level ownership is optional when every deployment supplies it.
Other string fields must also be non-empty. Malformed YAML and invalid settings fail before
network requests. Duplicate product names across files are rejected.

Reporters often name a product differently from NVD's CPE data. List those names so their version
data is used:

```yaml
tool:
  name: httpd
  repo: apache/httpd
  vendor: apache
  product: http_server
  aliases:
    - vendor: Apache Software Foundation
      product: Apache HTTP Server
```

Each alias needs exactly `vendor` and `product`. Names compare without regard to case, and aliases
do not change finding identity. Without a matching alias, a CVE whose description names the tool opens
a `needs-review` issue when NVD analysts have not listed any products.

## Multiple versions and environments

```yaml
tool:
  name: openbao
  display_name: OpenBao
  repo: openbao/openbao
  vendor: openbao
  product: openbao
  team: sre
  owner: default-owner
config:
  fix_days:
    critical: 2
    high: 7
    medium: 14
    low: 21
    unknown: null
    known_exploited: 2
deployments:
  - id: prod-eu
    environment: production
    version: "2.5.5"
    team: platform
    owner: production-owner
    config:
      fix_days:
        high: 3
  - id: stage
    environment: staging
    version: "2.6.4"
    owner: staging-owner
    config:
      notifications:
        slack:
          enabled: false
```

These are illustrative versions, not secure-version recommendations. `prod-eu` and `stage`
are scanned independently. Staging inherits `team: sre`; production overrides team and owner.
Each deployment can override any configuration setting, including destinations and credentials'
environment variable names.

| Deployment field | Required | Meaning |
| --- | --- | --- |
| `id` | Yes | Stable unique ID within the product; letters, numbers, hyphens or underscores; starts with a letter or number |
| `environment` | No | Human-readable environment; defaults to `id` |
| `version` | Yes | Quoted installed version for this deployment |
| `team` | Unless inherited | Responsible team for this deployment |
| `owner` | Unless inherited | Responsible owner for this deployment |
| `config` | No | Partial settings overriding tool and global settings |

The environment value `production` is shown as `PROD` in finding titles; the stored environment
and stable deployment ID remain unchanged.

Several installations in the same environment can use different IDs, for example `prod-eu`
and `prod-us`, both with `environment: production`. Keep the ID stable when upgrading or
changing ownership; the version and owner are not part of finding identity. Deployment entries
reject unknown fields and duplicate IDs. Product metadata stays under `tool`, outside the deployment entries.

## Complete OpenBao configuration

The [OpenBao inventory](../../../inventory/openbao.yaml) contains the complete settings currently
listed in root `config.yaml`, including every fix deadline, scanning, sources, GitHub, Jira and
Slack. It also includes two explicitly labelled demo deployments, not real deployed systems.
The sample keeps ownership on each deployment and omits optional `display_name`, so its
reported name defaults to `openbao`.

Explicit tool values override global values. Consequently, changing a global value will not
change OpenBao's matching explicit value. Remove the tool value to inherit it, or use `config: {}`
to inherit every global setting. Deployment overrides take precedence over tool values.
Nested mappings merge and lists replace inherited lists. Credentials stay in environment
variables; YAML holds variable names only. See [configuration](configuration.md).

## Single-version compatibility and reporting identity

Existing flat files with product metadata, `version`, `team` and `owner` at the root remain
supported. Grouped single-version files put metadata and ownership under `tool` and keep
`version` at the root. The two forms cannot be mixed. They retain the
legacy finding marker `tool/CVE`. A deployment record uses `tool/deployment-id/CVE` in every
tracker and Slack receipt. The same CVE can therefore create separate findings for production
and staging. Titles show the environment and deployment, bodies include ownership and version,
and tickets get a `deployment-ID` label in addition to the product label.

Converting a legacy record to `deployments` creates new identities. Existing unscoped tickets
and notification receipts are **not automatically migrated** because they do not identify an
environment. Review and reconcile old tickets manually; the scanner never closes them.
Renaming a deployment ID also creates a new reporting identity.
