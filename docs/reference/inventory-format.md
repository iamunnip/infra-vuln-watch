# Inventory format

Each tool has one `.yaml` file in `inventory/`.

| Field | Required | Example | Meaning |
| --- | --- | --- | --- |
| `name` | Yes | `openbao` | Short name, used in issue titles. Must be unique, with no spaces |
| `repo` | Yes | `openbao/openbao` | GitHub `owner/name` of the tool, used for the releases link |
| `version` | Yes | `"2.5.5"` | The version you run, in quotes |
| `team` | Yes | `sre` | Team responsible for this tool, shown in issues |
| `owner` | Yes | `iamunnip` | Who looks after this tool, shown in issues |
| `vendor` | Yes | `openbao` | Vendor name in NVD |
| `product` | Yes | `openbao` | Product name in NVD |
| `display_name` | No | `OpenBao` | Name shown in issues. Defaults to `name` |
| `keyword` | No | `openbao` | Word to search for in NVD. Defaults to `name` |

The scan stops with an error if a required field is missing, if `name` has spaces or is used
twice, if `version` has no quotes, or if `version` is not a valid version number.
