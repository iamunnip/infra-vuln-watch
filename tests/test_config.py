from datetime import date

import pytest

from infra_vuln_watch.configuration.config import load_config, merge_config, validate_config
from infra_vuln_watch.domain.fix_deadline import get_deadline


def test_missing_implicit_config_uses_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_config()['fix_days']['high'] == 7
    with pytest.raises(ValueError, match='could not read'):
        load_config(tmp_path / 'missing.yaml')


def test_loads_implicit_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'config.yaml').write_text('fix_days:\n  high: 5\n')
    policy = load_config()
    assert policy['fix_days']['high'] == 5
    assert policy['fix_days']['low'] == 21


def test_partial_override_preserves_global_values_without_mutation():
    global_config = merge_config({}, {'fix_days': {'high': 5, 'low': 30}})
    tool = merge_config(global_config, {'fix_days': {'high': 3}})
    assert tool['fix_days']['high'] == 3
    assert tool['fix_days']['low'] == 30
    tool['fix_days']['low'] = 1
    assert global_config['fix_days'] == {
        'critical': 2, 'high': 5, 'medium': 14, 'low': 30,
        'unknown': None, 'known_exploited': 2,
    }
    assert merge_config({}, {})['fix_days']['low'] == 21


@pytest.mark.parametrize('value', [None, [], {'typo': 1}, {'fix_days': None},
    {'fix_days': {'hihg': 5}}, {'fix_days': {'high': True}}, {'fix_days': {'high': 0}},
    {'fix_days': {'high': -1}}, {'fix_days': {'high': 1.5}}, {'fix_days': {'high': '5'}},
    {'fix_days': {'high': None}}, {'fix_days': {'high': 36501}}])
def test_invalid_policy_is_rejected(value):
    with pytest.raises(ValueError):
        validate_config(value)


def test_malformed_file_is_a_clean_error(tmp_path):
    path = tmp_path / 'settings.yaml'
    path.write_text('fix_days: [')
    with pytest.raises(ValueError, match='could not read'):
        load_config(path)


def test_custom_deadlines_and_kev_override():
    settings = {'fix_days': {'high': 4, 'known_exploited': 1, 'unknown': 10}}
    opened = date(2026, 11, 3)
    assert get_deadline('high', opened, config=settings) == {'days': 4, 'date': '2026-11-07'}
    assert get_deadline('high', opened, True, settings) == {'days': 1, 'date': '2026-11-04'}
    assert get_deadline('unknown', opened, config=settings)['days'] == 10


@pytest.mark.parametrize('overrides', [
    {'outputs': {'github': {'enabled': 'yes'}}},
    {'outputs': {'github': {'repository': 'bad-repo'}}},
    {'outputs': {'github': {'api_url': 'http://example.test'}}},
    {'outputs': {'jira': {'fields': {'description': 'cannot overwrite identity'}}}},
    {'notifications': {'slack': {'webhook_env': 'https://secret'}}},
    {'scan': {'min_severity': 'urgent'}},
    {'scan': {'ignore_cves': [12]}},
    {'sources': {'nvd': {'interval_without_key': 0.1}}},
    {'sources': {'nvd': {'max_attempts': 1.5}}},
    {'sources': {'epss': {'batch_size': 101}}},
])
def test_invalid_routing_and_scan_settings_fail_validation(overrides):
    with pytest.raises(ValueError):
        merge_config({}, overrides)


def test_recursive_overrides_and_list_replacement():
    global_config = {'outputs': {'jira': {'base_url': 'https://example.atlassian.net',
        'project': 'SEC', 'fields': {'priority': {'name': 'High'}}}},
        'scan': {'ignore_cves': ['one', 'two']}}
    merged = merge_config(global_config, {'outputs': {'jira': {'enabled': True}},
        'scan': {'ignore_cves': ['three']}})
    assert merged['outputs']['jira']['project'] == 'SEC'
    assert merged['outputs']['jira']['fields'] == {'priority': {'name': 'High'}}
    assert merged['scan']['ignore_cves'] == ['three']
    assert global_config['scan']['ignore_cves'] == ['one', 'two']


def test_cross_field_requirements_apply_to_resolved_tool():
    from infra_vuln_watch.configuration.config import validate_effective
    with pytest.raises(ValueError, match='base_url and project'):
        validate_effective(merge_config({}, {'outputs': {'jira': {'enabled': True}}}))
    with pytest.raises(ValueError, match='one NVD search'):
        validate_effective(merge_config({}, {'sources': {'nvd': {'product_search': False, 'keyword_search': False}}}))
