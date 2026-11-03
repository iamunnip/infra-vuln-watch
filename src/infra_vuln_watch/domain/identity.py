"""Stable scan and finding identities independent of installed version."""

import re

MARKER_PATTERN = re.compile(r'<!-- vuln-watch-id: (\S+) -->')


def inventory_id(item):
    deployment = item.get('deployment_id')
    return f"{item['name']}/{deployment}" if deployment else item['name']


def finding_id(item, cve):
    return f"{inventory_id(item)}/{cve['id']}"


def finding_marker(item, cve):
    """Return the hidden text that lets us find this finding's ticket on later runs."""
    return f"<!-- vuln-watch-id: {finding_id(item, cve)} -->"


def target_name(item):
    name = item['display_name']
    if item.get('deployment_id'):
        environment = item['environment']
        deployment = item['deployment_id']
        scope = environment if environment == deployment else f'{environment}/{deployment}'
        return f'{name} [{scope}]'
    return name
