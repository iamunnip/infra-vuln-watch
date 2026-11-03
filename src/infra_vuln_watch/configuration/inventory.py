"""Load tool inventory and expand deployment-specific scan targets."""

from pathlib import Path
import re

import yaml
from packaging.version import InvalidVersion, Version

from infra_vuln_watch.configuration.config import merge_overrides, validate_config
from infra_vuln_watch.domain.identity import inventory_id

PRODUCT_FIELDS = ['name', 'repo', 'vendor', 'product']
TARGET_FIELDS = ['version', 'team', 'owner']
DEPLOYMENT_FIELDS = {'id', 'environment', 'version', 'team', 'owner', 'config'}
TOOL_FIELDS = set(PRODUCT_FIELDS) | {'display_name', 'keyword', 'team', 'owner', 'aliases'}


def normalise_document(document, source):
    """Flatten grouped tool metadata internally while accepting legacy flat files."""
    if 'tool' not in document:
        return document
    metadata = document['tool']
    if not isinstance(metadata, dict):
        raise ValueError(f'{source}: tool must be a mapping')
    mixed = TOOL_FIELDS & document.keys()
    if mixed:
        raise ValueError(f'{source}: keep product metadata inside tool; do not mix grouped and flat fields')
    unknown_tool = metadata.keys() - TOOL_FIELDS
    if unknown_tool:
        raise ValueError(f'{source}: unknown tool fields: {", ".join(map(str, unknown_tool))}')
    unknown_root = document.keys() - {'tool', 'config', 'deployments', 'version'}
    if unknown_root:
        raise ValueError(f'{source}: unknown inventory sections: {", ".join(map(str, unknown_root))}')
    return {**metadata, **{key: value for key, value in document.items() if key != 'tool'}}


def require_strings(item, fields, source):
    for field in fields:
        if field not in item or item[field] is None or item[field] == '':
            raise ValueError(f"{source}: missing required field '{field}'")
        if not isinstance(item[field], str) or not item[field].strip():
            if field == 'version':
                raise ValueError(f'{source}: put quotes around the version, like version: "2.7.2"')
            raise ValueError(f"{source}: '{field}' must be a non-empty string")


def validate_aliases(item, source):
    """Check the other vendor and product names that reporters use for this tool."""
    aliases = item.get('aliases', [])
    if not isinstance(aliases, list):
        raise ValueError(f'{source}: aliases must be a list of vendor and product names')
    for alias in aliases:
        if not isinstance(alias, dict) or alias.keys() != {'vendor', 'product'}:
            raise ValueError(f'{source}: each alias must have only vendor and product')
        require_strings(alias, ['vendor', 'product'], f'{source}: alias')


def validate_target(item, source):
    require_strings(item, TARGET_FIELDS, source)
    try:
        Version(item['version'])
    except InvalidVersion:
        raise ValueError(f"{source}: '{item['version']}' is not a valid version") from None


def expand_deployments(item, source):
    """Produce independent targets; merge tool and deployment settings without injecting defaults."""
    if 'deployments' not in item:
        validate_target(item, source)
        return [item]
    deployments = item['deployments']
    if not isinstance(deployments, list) or not deployments:
        raise ValueError(f'{source}: deployments must be a non-empty list')
    if 'version' in item:
        raise ValueError(f'{source}: put version inside each deployment, not at the tool level')
    targets = []
    seen = set()
    common = {key: value for key, value in item.items() if key != 'deployments'}
    for deployment in deployments:
        if not isinstance(deployment, dict):
            raise ValueError(f'{source}: each deployment must be a mapping')
        unknown = deployment.keys() - DEPLOYMENT_FIELDS
        if unknown:
            raise ValueError(f'{source}: unknown deployment fields: {", ".join(map(str, unknown))}')
        identifier = deployment.get('id')
        if not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', identifier):
            raise ValueError(f'{source}: deployment id must use letters, numbers, hyphens or underscores')
        if identifier in seen:
            raise ValueError(f"{source}: duplicate deployment id '{identifier}'")
        seen.add(identifier)
        label = f'{source}: deployment {identifier}'
        overrides = deployment.get('config', {})
        validate_config(overrides, f'{label}: config')
        target = {**common, **{key: value for key, value in deployment.items() if key not in {'id', 'config'}}}
        target['deployment_id'] = identifier
        target.setdefault('environment', identifier)
        require_strings(target, ['environment'], label)
        target['config'] = merge_overrides(item.get('config', {}), overrides)
        validate_target(target, label)
        targets.append(target)
    return targets


def load_item(path):
    """Read and validate one tool document, preserving the public single-record helper."""
    try:
        with open(path, encoding='utf-8') as file:
            item = yaml.safe_load(file)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError(f'{path}: could not read inventory: {error}') from error
    if not isinstance(item, dict):
        raise ValueError(f"{path}: expected a list of fields like 'name: openbao'")
    item = normalise_document(item, path)
    require_strings(item, PRODUCT_FIELDS, path)
    if any(character.isspace() for character in item['name']):
        raise ValueError(f'{path}: name cannot contain spaces, use a dash instead')
    for field in ('keyword', 'display_name', 'team', 'owner'):
        if field in item:
            require_strings(item, [field], path)
    validate_aliases(item, path)
    item.setdefault('keyword', item['name'])
    item.setdefault('display_name', item['name'])
    if 'config' in item:
        validate_config(item['config'], f'{path}: config')
    expand_deployments(item, path)
    return item


def load_inventory(directory):
    """Return one validated scan target per legacy record or deployment."""
    paths = sorted([*Path(directory).glob('*.yaml'), *Path(directory).glob('*.yml')])
    if not paths:
        raise ValueError(f'No .yaml or .yml files found in {directory}')
    items = []
    names = set()
    identifiers = set()
    for path in paths:
        document = load_item(path)
        if document['name'] in names:
            raise ValueError(f"Two inventory files use the name '{document['name']}'")
        names.add(document['name'])
        for target in expand_deployments(document, path):
            identifier = inventory_id(target)
            if identifier in identifiers:
                raise ValueError(f"{path}: duplicate scan target identity '{identifier}'")
            identifiers.add(identifier)
            items.append(target)
    return items
