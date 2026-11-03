from unittest.mock import Mock

import pytest

from infra_vuln_watch.application import scanner
from infra_vuln_watch.configuration.config import merge_config


def tool(overrides=None):
    return {'name': 'tool', 'vendor': 'o', 'product': 'tool', 'version': '1.0',
            'config': merge_config({}, overrides or {})}


def cve(identifier, score=None, versions=True):
    value = {'id': identifier}
    if score is not None:
        value['metrics'] = {'cvssMetricV31': [{'cvssData': {'baseScore': score, 'version': '3.1'}}]}
    if versions:
        value['affected'] = [{'affectedData': [{'vendor': 'o', 'product': 'tool',
            'versions': [{'version': '< 2.0', 'status': 'affected'}]}]}]
    return value


def test_severity_filter_keeps_unknown_unless_explicitly_disabled(monkeypatch):
    monkeypatch.setattr(scanner.nvd_client, 'fetch_cves', lambda item: [
        cve('low', 2), cve('high', 8), cve('unscored'), cve('zero', 0),
    ])
    assert [value['id'] for value, _ in scanner.find_problems(tool({'scan': {'min_severity': 'high'}}))] == ['high', 'unscored']
    settings = {'scan': {'min_severity': 'high', 'include_unknown_severity': False}}
    assert [value['id'] for value, _ in scanner.find_problems(tool(settings))] == ['high']


def test_unknown_version_and_ignore_filters_are_independent(monkeypatch):
    monkeypatch.setattr(scanner.nvd_client, 'fetch_cves', lambda item: [
        cve('ignore', 9), cve('unknown-version', 9, versions=False), cve('keep', 8),
    ])
    settings = {'scan': {'report_unknown_versions': False, 'ignore_cves': ['ignore']}}
    assert [value['id'] for value, _ in scanner.find_problems(tool(settings))] == ['keep']


def test_disabled_tools_make_no_calls(monkeypatch):
    outputs = Mock()
    fetch = Mock()
    monkeypatch.setattr(scanner, 'OutputRouter', outputs)
    monkeypatch.setattr(scanner.nvd_client, 'fetch_cves', fetch)
    assert scanner.run_scan([tool({'scan': {'enabled': False}})]) == 0
    outputs.assert_not_called()
    fetch.assert_not_called()


def test_invalid_cve_data_fails_run_instead_of_a_traceback(monkeypatch):
    output = Mock()
    monkeypatch.setattr(scanner, 'OutputRouter', Mock(return_value=output))
    monkeypatch.setattr(scanner.risk_data, 'fetch_kev', lambda **kwargs: {})
    monkeypatch.setattr(scanner.nvd_client, 'fetch_cves', lambda item: [{'id': 'bad', 'metrics': {'cvssMetricV31': [{}]}}])
    assert scanner.run_scan([tool()]) == 1
    output.report.assert_not_called()
