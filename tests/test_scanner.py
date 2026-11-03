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


def exploited(identifier, score=5):
    return {**cve(identifier, score), 'cisaExploitAdd': '2026-01-02'}


def test_known_exploited_cve_passes_severity_filters():
    settings = {'scan': {'min_severity': 'critical', 'include_unknown_severity': False}}
    candidates = [exploited('nvd-copy'), cve('catalog', 5), cve('catalog-unscored'), cve('plain', 5),
                  {**exploited('unscored'), 'metrics': {}}]
    entry = {'date_added': '2026-01-02'}
    kev = {'catalog': entry, 'catalog-unscored': entry}
    found = [value['id'] for value, _ in scanner.find_problems(tool(settings), candidates=candidates, kev=kev)]
    assert found == ['nvd-copy', 'catalog', 'catalog-unscored', 'unscored']


def test_known_exploited_cve_still_respects_explicit_exclusions():
    settings = {'scan': {'min_severity': 'critical', 'ignore_cves': ['ignored']}}
    candidates = [exploited('ignored'), exploited('zero', 0), {**exploited('rejected'), 'vulnStatus': 'Rejected'}]
    assert scanner.find_problems(tool(settings), candidates=candidates) == []


def test_nvd_kev_copy_does_not_pass_filters_when_fallback_is_disabled():
    settings = {'scan': {'min_severity': 'critical'}, 'sources': {'kev': {'nvd_fallback': False}}}
    assert scanner.find_problems(tool(settings), candidates=[exploited('nvd-copy')]) == []


@pytest.mark.parametrize('bad', [
    {'id': 'bad', 'metrics': {'cvssMetricV31': [{}]}},
    {'id': 'bad', 'affected': [{'affectedData': ['not a mapping']}]},
])
def test_malformed_cve_does_not_block_other_findings(monkeypatch, capsys, bad):
    output = Mock()
    output.report.return_value = True
    monkeypatch.setattr(scanner, 'OutputRouter', Mock(return_value=output))
    monkeypatch.setattr(scanner.risk_data, 'fetch_kev', lambda **kwargs: {})
    monkeypatch.setattr(scanner.risk_data, 'fetch_epss', lambda *args, **kwargs: {})
    monkeypatch.setattr(scanner.nvd_client, 'fetch_cves', lambda item: [bad, cve('good', 9)])
    assert scanner.run_scan([{**tool(), 'keyword': 'tool'}]) == 1
    assert [call.args[1]['id'] for call in output.report.call_args_list] == ['good']
    assert 'FAILED: invalid vulnerability data for bad' in capsys.readouterr().out


def test_failure_while_formatting_one_finding_does_not_block_the_next(monkeypatch):
    output = Mock()
    output.report.side_effect = [AttributeError('bad data'), True]
    monkeypatch.setattr(scanner, 'OutputRouter', Mock(return_value=output))
    monkeypatch.setattr(scanner.risk_data, 'fetch_kev', lambda **kwargs: {})
    monkeypatch.setattr(scanner.risk_data, 'fetch_epss', lambda *args, **kwargs: {})
    monkeypatch.setattr(scanner.nvd_client, 'fetch_cves', lambda item: [cve('first', 9), cve('second', 9)])
    assert scanner.run_scan([{**tool(), 'keyword': 'tool'}]) == 1
    assert output.report.call_count == 2


def test_aliases_and_keyword_reach_version_matching():
    named = {'affected': [{'affectedData': [{'vendor': 'Other Name', 'product': 'Tool Server',
                                             'versions': [{'version': '< 2.0', 'status': 'affected'}]}]}]}
    item = {**tool(), 'aliases': [{'vendor': 'Other Name', 'product': 'Tool Server'}]}
    (_, result), = scanner.find_problems(item, candidates=[{'id': 'named', **named}])
    assert result['status'] == 'affected'
    mentioned = {'id': 'mentioned', 'descriptions': [{'lang': 'en', 'value': 'Tool leaks a key.'}],
                 'affected': [{'affectedData': [{'vendor': 'x', 'product': 'y', 'versions': []}]}]}
    (_, result), = scanner.find_problems({**tool(), 'keyword': 'tool'}, candidates=[mentioned])
    assert result['status'] == 'unknown'
