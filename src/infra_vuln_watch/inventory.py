"""Read the YAML files in the inventory directory."""

from pathlib import Path

import yaml
from packaging.version import InvalidVersion, Version

REQUIRED_FIELDS = ["name", "repo", "version", "owner", "vendor", "product"]


def load_item(path):
    """Read one inventory file and check that it is valid."""
    with open(path, encoding="utf-8") as file:
        item = yaml.safe_load(file)

    if not isinstance(item, dict):
        raise ValueError(f"{path}: expected a list of fields like 'name: openbao'")

    for field in REQUIRED_FIELDS:
        if not item.get(field):
            raise ValueError(f"{path}: missing required field '{field}'")

    # Spaces would break the hidden id we use to find this issue on later runs.
    if " " in item["name"]:
        raise ValueError(f"{path}: name cannot contain spaces, use a dash instead")

    # Without quotes, YAML reads 2.10 as the number 2.1, which is a wrong version.
    if not isinstance(item["version"], str):
        raise ValueError(f'{path}: put quotes around the version, like version: "2.7.2"')

    try:
        Version(item["version"])
    except InvalidVersion:
        raise ValueError(f"{path}: '{item['version']}' is not a valid version") from None

    # The word to search for in NVD. Most tools can just use their name.
    item.setdefault("keyword", item["name"])
    return item


def load_inventory(directory):
    """Read every .yaml file in the directory and return a list of items."""
    paths = sorted(Path(directory).glob("*.yaml"))
    if not paths:
        raise ValueError(f"No .yaml files found in {directory}")
    items = [load_item(path) for path in paths]

    # Issues are tracked by name, so two items with one name would share issues.
    names = [item["name"] for item in items]
    for name in names:
        if names.count(name) > 1:
            raise ValueError(f"Two inventory files use the name '{name}'")
    return items
