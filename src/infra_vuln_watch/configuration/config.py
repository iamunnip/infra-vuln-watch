"""Validated global settings and recursively merged per-tool overrides."""

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

import yaml

from infra_vuln_watch.domain.ignore_list import expiry_date

DEFAULT_CONFIG: dict[str, Any] = {
    "fix_days": {"critical": 2, "high": 7, "medium": 14, "low": 21,
                 "unknown": None, "known_exploited": 2},
    "scan": {"enabled": True, "dry_run": False, "min_severity": "low",
             "include_unknown_severity": True, "report_unknown_versions": True, "ignore_cves": [],
             "update_existing": True},
    "sources": {
        # NVD allows 5 requests per 30 seconds, or 50 per 30 seconds with an API key.
        "nvd": {"product_search": True, "keyword_search": True, "timeout": 60,
                "max_attempts": 5, "retry_wait": 30,
                "interval_without_key": 6.5, "interval_with_key": 0.7, "api_key_env": "NVD_API_KEY"},
        "epss": {"enabled": True, "timeout": 60, "max_attempts": 3, "retry_wait": 5, "batch_size": 100},
        "kev": {"enabled": True, "nvd_fallback": True, "timeout": 60, "max_attempts": 3, "retry_wait": 5},
    },
    "outputs": {
        "github": {"enabled": True, "repository": None, "token_env": "GITHUB_TOKEN",
                   "api_url": "https://api.github.com", "timeout": 30, "create_wait": 3, "max_rate_limit_wait": 120},
        "jira": {"enabled": False, "base_url": "", "project": "", "issue_type": "Task",
                 "email_env": "JIRA_EMAIL", "token_env": "JIRA_API_TOKEN", "timeout": 30,
                 "create_wait": 1, "max_rate_limit_wait": 120, "fields": {}},
    },
    "notifications": {
        "slack": {"enabled": False, "webhook_env": "SLACK_WEBHOOK_URL", "timeout": 30,
                  "repeat": False, "state_file": ".vuln-watch/slack.json", "send_wait": 1, "max_rate_limit_wait": 120,
                  "notify_updates": True},
    },
}
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SEVERITIES = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_ignore_entry(entry, location):
    """Accept a CVE ID, or a mapping with id and an optional reason and expiry date."""
    if isinstance(entry, str):
        cve_id = entry
    elif isinstance(entry, dict) and 'id' in entry and not entry.keys() - {'id', 'reason', 'expires'}:
        cve_id = entry['id']
        reason = entry.get('reason')
        if reason is not None and (not isinstance(reason, str) or not reason.strip()):
            raise ValueError(f"{location}: reason must be a non-empty string")
        if entry.get('expires') is not None:
            try:
                expiry_date(entry['expires'])
            except (TypeError, ValueError):
                raise ValueError(f"{location}: expires must be a date like 2027-01-31") from None
    else:
        raise ValueError(f"{location}: expected a CVE ID, or a mapping with id, reason and expires")
    # A mistyped ID would otherwise match nothing and hide the mistake.
    if not isinstance(cve_id, str) or not CVE_ID.fullmatch(cve_id):
        raise ValueError(f"{location}: expected a CVE ID like CVE-2026-1234")


def https_url(value):
    parsed = urlsplit(value)
    return (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username
            and not parsed.password and not parsed.query and not parsed.fragment)


def _validate(value, defaults, path):
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a mapping")
    for key, setting in value.items():
        location = f"{path}.{key}"
        if key not in defaults:
            raise ValueError(f"{path}: unknown setting '{key}'")
        default = defaults[key]
        if location.endswith('.jira.fields'):
            if not isinstance(setting, dict) or any(not isinstance(k, str) for k in setting):
                raise ValueError(f"{location}: expected a mapping with string field names")
            if {'project', 'issuetype', 'summary', 'description', 'labels'} & setting.keys():
                raise ValueError(f"{location}: cannot replace project, issuetype, summary, description or labels")
            # Only JSON-compatible values may reach the Jira request.
            try:
                json.dumps(setting, allow_nan=False)
            except (TypeError, ValueError) as error:
                raise ValueError(f"{location}: fields must be JSON-compatible") from error
        elif isinstance(default, dict):
            _validate(setting, default, location)
        elif '.fix_days.' in location:
            if key == 'unknown' and setting is None:
                continue
            if type(setting) is not int or not 1 <= setting <= 36500:
                raise ValueError(f"{location}: expected an integer from 1 to 36500")
        elif type(default) is bool:
            if type(setting) is not bool:
                raise ValueError(f"{location}: expected a boolean")
        elif key == 'repository':
            if setting is not None and (not isinstance(setting, str) or not re.fullmatch(r'[\w.-]+/[\w.-]+', setting)):
                raise ValueError(f"{location}: expected owner/repository or null")
        elif isinstance(default, str):
            if not isinstance(setting, str) or not setting.strip():
                # Empty Jira connection fields are allowed only while disabled; checked after merging.
                if key not in {'base_url', 'project'} or setting != '':
                    raise ValueError(f"{location}: expected a non-empty string")
            if key.endswith('_env') and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', setting):
                raise ValueError(f"{location}: expected an environment variable name")
            if key == 'min_severity' and setting not in SEVERITIES:
                raise ValueError(f"{location}: expected low, medium, high or critical")
            if key in {'api_url', 'base_url'} and setting and not https_url(setting):
                raise ValueError(f"{location}: expected an HTTPS URL without credentials, query or fragment")
            if key == 'project' and setting and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', setting):
                raise ValueError(f"{location}: expected a Jira project key")
        elif key == 'ignore_cves':
            if not isinstance(setting, list):
                raise ValueError(f"{location}: expected a list")
            for entry in setting:
                validate_ignore_entry(entry, location)
        elif isinstance(default, (int, float)):
            minimum = {'interval_without_key': 6.5, 'interval_with_key': 0.7,
                       'retry_wait': 0, 'create_wait': 1 if '.jira.' in location else 3,
                       'send_wait': 1, 'max_rate_limit_wait': 0}.get(key, 1)
            maximum = {'max_attempts': 10, 'batch_size': 100, 'timeout': 300}.get(key, 3600)
            if (type(setting) not in (int, float) or not minimum <= setting <= maximum
                    or (key in {'max_attempts', 'batch_size'} and type(setting) is not int)):
                raise ValueError(f"{location}: expected a number from {minimum} to {maximum}")


def validate_config(value, source="config"):
    """Validate partial overrides; cross-field requirements apply after merging."""
    _validate(value, DEFAULT_CONFIG, source)
    return value


def _merge(base, overrides):
    result = deepcopy(base) if isinstance(base, dict) else {}
    for key, value in overrides.items():
        result[key] = _merge(result.get(key, {}), value) if isinstance(value, dict) else deepcopy(value)
    return result


def merge_config(global_config, overrides):
    """Resolve defaults < global settings < tool overrides; lists replace inherited lists."""
    validate_config(global_config)
    validate_config(overrides)
    return _merge(_merge(DEFAULT_CONFIG, global_config), overrides)


def merge_overrides(tool_config, deployment_config):
    """Merge partial inventory layers without replacing inherited global values with defaults."""
    validate_config(tool_config)
    validate_config(deployment_config)
    return _merge(tool_config, deployment_config)


def validate_effective(config, source="config"):
    """Check requirements for enabled integrations after all overrides have been applied."""
    if not config['scan']['enabled']:
        return
    nvd = config['sources']['nvd']
    if not nvd['product_search'] and not nvd['keyword_search']:
        raise ValueError(f"{source}: at least one NVD search must be enabled")
    jira = config['outputs']['jira']
    if jira['enabled'] and (not jira['base_url'] or not jira['project']):
        raise ValueError(f"{source}: enabled Jira requires base_url and project")


def load_config(path=None):
    """Read optional config.yaml, or require an explicitly selected configuration file."""
    selected = Path(path) if path is not None else Path("config.yaml")
    if path is None and not selected.exists():
        return merge_config({}, {})
    try:
        data = yaml.safe_load(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ValueError(f"{selected}: could not read configuration: {error}") from error
    validate_config(data, str(selected))
    return merge_config(data, {})
