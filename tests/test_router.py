from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.configuration.config import merge_config
from infra_vuln_watch.application import router

CVE = {'id': 'CVE-2026-1234'}
RESULT = {'status': 'affected', 'fix': None, 'affected_versions': []}
RISK = {'kev': {}, 'epss': {}}


def item(name='tool', overrides=None):
    return {'name': name, 'display_name': name, 'repo': 'o/tool', 'team': 'sre', 'owner': 'me',
            'version': '1.0', 'vendor': 'o', 'product': 'tool', 'keyword': 'tool',
            'config': merge_config({}, overrides or {})}


@pytest.fixture
def clients(monkeypatch):
    monkeypatch.setenv('GITHUB_TOKEN', 'token')
    monkeypatch.setenv('GITHUB_REPOSITORY', 'o/r')
    monkeypatch.setenv('JIRA_EMAIL', 'email')
    monkeypatch.setenv('JIRA_API_TOKEN', 'token')
    monkeypatch.setenv('SLACK_WEBHOOK_URL', 'https://hooks.slack.com/services/test/space/secret')
    github = Mock()
    github.get_reported_ids.return_value = set()
    github.create_issue.return_value = 'https://github.com/o/r/issues/1'
    jira = Mock()
    jira.get_reported_ids.return_value = set()
    jira.create_issue.return_value = 'https://example.atlassian.net/browse/SEC-1'
    slack = Mock()
    slack.needs_delivery.return_value = True
    monkeypatch.setattr(router.github_client, 'GitHubClient', Mock(return_value=github))
    monkeypatch.setattr(router.jira_client, 'JiraClient', Mock(return_value=jira))
    monkeypatch.setattr(router.slack_client, 'SlackClient', Mock(return_value=slack))
    return github, jira, slack


def both():
    return {'outputs': {'jira': {'enabled': True, 'base_url': 'https://example.atlassian.net', 'project': 'SEC'}}}


def test_github_history_does_not_suppress_missing_jira_ticket(clients):
    github, jira, _ = clients
    github.get_reported_ids.return_value = {'tool/CVE-2026-1234'}
    tool = item(overrides=both())
    output = router.OutputRouter([tool])
    assert output.needs_reporting(tool, CVE)
    assert output.report(tool, CVE, RESULT, RISK)
    github.create_issue.assert_not_called()
    jira.create_issue.assert_called_once()
    assert not output.needs_reporting(tool, CVE)


def test_delivery_failure_does_not_stop_other_destinations(clients):
    github, jira, _ = clients
    github.create_issue.side_effect = requests.ConnectionError('secret-do-not-print')
    tool = item(overrides=both())
    output = router.OutputRouter([tool])
    assert not output.report(tool, CVE, RESULT, RISK)
    jira.create_issue.assert_called_once()
    # Jira succeeded and will not be recreated when GitHub is retried in this process.
    assert not output.report(tool, CVE, RESULT, RISK)
    assert jira.create_issue.call_count == 1


def test_missing_enabled_secret_fails_before_remote_setup(clients, monkeypatch, tmp_path):
    github, _, _ = clients
    monkeypatch.delenv('SLACK_WEBHOOK_URL')
    tool = item(overrides={'notifications': {'slack': {'enabled': True, 'state_file': str(tmp_path / 'state.json')}}})
    with pytest.raises(ValueError, match='SLACK_WEBHOOK_URL'):
        router.OutputRouter([tool])
    github.create_missing_labels.assert_not_called()


def test_dry_run_skips_all_outputs_and_state(clients, monkeypatch, tmp_path):
    github, jira, slack = clients
    monkeypatch.delenv('GITHUB_TOKEN')
    config = both()
    config['notifications'] = {'slack': {'enabled': True, 'state_file': str(tmp_path / 'absent/state.json')}}
    tool = item(overrides=config)
    output = router.OutputRouter([tool], dry_run=True)
    assert output.report(tool, CVE, RESULT, RISK)
    github.create_missing_labels.assert_not_called()
    jira.get_reported_ids.assert_not_called()
    slack.send.assert_not_called()
    assert not (tmp_path / 'absent').exists()


def test_console_only_needs_no_github_credentials(clients, monkeypatch):
    monkeypatch.delenv('GITHUB_TOKEN')
    tool = item(overrides={'outputs': {'github': {'enabled': False}}})
    output = router.OutputRouter([tool])
    assert output.report(tool, CVE, RESULT, RISK)
    clients[0].create_missing_labels.assert_not_called()


def test_per_tool_repository_routing_uses_separate_clients(clients):
    a = item('a', {'outputs': {'github': {'repository': 'org/a'}}})
    b = item('b', {'outputs': {'github': {'repository': 'org/b'}}})
    router.OutputRouter([a, b])
    calls = router.github_client.GitHubClient.call_args_list
    assert [call.args[1] for call in calls] == ['org/a', 'org/b']


def test_slack_failure_can_retry_without_recreating_ticket(clients, tmp_path, capsys):
    github, _, slack = clients
    slack.send.side_effect = requests.ConnectionError('secret-url')
    tool = item(overrides={'notifications': {'slack': {'enabled': True, 'state_file': str(tmp_path / 'state.json')}}})
    output = router.OutputRouter([tool])
    assert not output.report(tool, CVE, RESULT, RISK)
    slack.send.side_effect = None
    assert output.report(tool, CVE, RESULT, RISK)
    assert github.create_issue.call_count == 1
    assert slack.send.call_count == 2
    assert 'secret-url' not in capsys.readouterr().out


def test_deployments_share_product_but_have_independent_routes(clients):
    github, jira, _ = clients
    prod = {**item(), 'deployment_id': 'production', 'environment': 'production'}
    stage = {**item(overrides=both()), 'deployment_id': 'staging', 'environment': 'staging'}
    github.get_reported_ids.return_value = {'tool/production/CVE-2026-1234'}
    output = router.OutputRouter([prod, stage])
    assert not output.needs_reporting(prod, CVE)
    assert output.needs_reporting(stage, CVE)
    assert output.report(stage, CVE, RESULT, RISK)
    jira.create_issue.assert_called_once()
    assert 'tool/staging/CVE-2026-1234' in jira.create_issue.call_args.args[1]


def test_shared_title_format_is_used_for_github_jira_and_slack(clients, tmp_path):
    github, jira, slack = clients
    config = both()
    config['notifications'] = {'slack': {'enabled': True, 'state_file': str(tmp_path / 'state.json')}}
    target = {**item(overrides=config), 'environment': 'stage', 'deployment_id': 'stage-eu'}
    output = router.OutputRouter([target])
    assert output.report(target, CVE, RESULT, RISK)
    title = github.create_issue.call_args.args[0]
    assert title.startswith('[UNKNOWN] [STAGE/stage-eu] [n/a] CVE-2026-1234 tool -')
    assert jira.create_issue.call_args.args[0] == title
    assert slack.send.call_args.args[1] == title
