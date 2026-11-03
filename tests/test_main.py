from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.clients import github_client
from infra_vuln_watch.cli import main
from infra_vuln_watch.clients import nvd_client
from infra_vuln_watch.clients import risk_data

GOOD = 'name: tool\nrepo: o/tool\nversion: "1.0.0"\nteam: sre\nowner: me\nvendor: o\nproduct: tool\n'


def make_cve(cve_id, version_text, status="Analyzed"):
    data = {"vendor": "o", "product": "tool", "versions": [{"version": version_text, "status": "affected"}]}
    return {"id": cve_id, "vulnStatus": status, "affected": [{"affectedData": [data]}]}


@pytest.fixture(autouse=True)
def fake_risk_data(monkeypatch):
    """Stop these tests from calling the real EPSS and CISA services."""
    monkeypatch.setattr(risk_data, "fetch_kev", lambda **kwargs: {})
    monkeypatch.setattr(risk_data, "fetch_epss", lambda cve_ids, **kwargs: {})


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    (tmp_path / "tool.yaml").write_text(GOOD)
    monkeypatch.setattr("sys.argv", ["main.py", "--inventory", str(tmp_path)])
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def github(monkeypatch):
    fake = Mock()
    fake.get_reported_ids.return_value = {"tool/CVE-OLD"}
    monkeypatch.setattr(github_client, "GitHubClient", Mock(return_value=fake))
    return fake


def titles(github):
    return [call.args[0] for call in github.create_issue.call_args_list]


def test_opens_issues_only_for_new_cves_that_affect_us(inventory, github, monkeypatch):
    cves = [
        make_cve("CVE-NEW", "< 2.0.0"),
        make_cve("CVE-OLD", "< 2.0.0"),
        make_cve("CVE-FIXED", "< 0.5.0"),
        make_cve("CVE-GONE", "< 2.0.0", status="Rejected"),
    ]
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: cves)

    assert main.main() == 0
    assert len(titles(github)) == 1
    assert "CVE-NEW" in titles(github)[0]
    assert "tool-tool" in github.create_issue.call_args.args[2]


def test_unconfirmed_cve_gets_the_review_label(inventory, github, monkeypatch):
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: [make_cve("CVE-X", "2.x")])

    assert main.main() == 0
    assert "needs-review" in github.create_issue.call_args.args[2]


def test_failed_scan_exits_with_an_error(inventory, github, monkeypatch):
    def broken(item):
        raise requests.RequestException("NVD is down")

    monkeypatch.setattr(nvd_client, "fetch_cves", broken)
    assert main.main() == 1


def test_one_failed_item_does_not_stop_the_others(inventory, github, monkeypatch):
    (inventory / "another.yaml").write_text(GOOD.replace("name: tool", "name: another"))

    def fetch(item):
        if item["name"] == "another":
            raise requests.RequestException("NVD is down")
        return [make_cve("CVE-NEW", "< 2.0.0")]

    monkeypatch.setattr(nvd_client, "fetch_cves", fetch)
    assert main.main() == 1
    assert len(titles(github)) == 1


def test_dry_run_opens_nothing_and_needs_no_token(inventory, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["main.py", "--inventory", str(inventory), "--dry-run"])
    monkeypatch.delenv("GITHUB_TOKEN")
    client = Mock()
    monkeypatch.setattr(github_client, "GitHubClient", client)
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: [make_cve("CVE-NEW", "< 2.0.0")])

    assert main.main() == 0
    client.assert_not_called()
    assert "CVE-NEW" in capsys.readouterr().out


def test_missing_token_is_an_error(inventory, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN")
    assert main.main() == 1


def test_bad_inventory_is_a_clean_error(inventory, capsys):
    (inventory / "tool.yaml").write_text("name: tool\n")
    assert main.main() == 1
    assert "Configuration or inventory problem" in capsys.readouterr().out


def test_github_down_at_start_is_a_clean_error(inventory, github):
    github.create_missing_labels.side_effect = requests.RequestException("down")
    assert main.main() == 1


def test_score_of_zero_is_skipped_but_a_missing_score_is_not(inventory, github, monkeypatch):
    zero = make_cve("CVE-ZERO", "< 2.0.0")
    zero["metrics"] = {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 0.0}}]}
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: [zero, make_cve("CVE-NOSCORE", "< 2.0.0")])

    assert main.main() == 0
    assert len(titles(github)) == 1
    assert "CVE-NOSCORE" in titles(github)[0]


def test_known_exploited_cve_gets_its_label(inventory, github, monkeypatch):
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: [make_cve("CVE-NEW", "< 2.0.0")])
    monkeypatch.setattr(risk_data, "fetch_kev", lambda **kwargs: {"CVE-NEW": {"date_added": "d", "due_date": "d", "required_action": "a", "ransomware": "r"}})

    assert main.main() == 0
    assert "known-exploited" in github.create_issue.call_args.args[2]


def test_risk_data_being_down_does_not_fail_the_scan(inventory, github, monkeypatch):
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: [make_cve("CVE-NEW", "< 2.0.0")])
    monkeypatch.setattr(risk_data, "fetch_kev", lambda **kwargs: None)
    monkeypatch.setattr(risk_data, "fetch_epss", lambda cve_ids, **kwargs: None)

    assert main.main() == 0
    assert "| EPSS | Could not check |" in github.create_issue.call_args.args[1]


def test_epss_is_only_requested_for_new_cves(inventory, github, monkeypatch):
    monkeypatch.setattr(nvd_client, "fetch_cves", lambda item: [make_cve("CVE-NEW", "< 2.0.0"), make_cve("CVE-OLD", "< 2.0.0")])
    fake_epss = Mock(return_value={})
    monkeypatch.setattr(risk_data, "fetch_epss", fake_epss)

    main.main()
    assert fake_epss.call_args.args[0] == ["CVE-NEW"]


def test_config_overrides_reach_issue_body(inventory, github, monkeypatch):
    settings = inventory / 'settings.yml'
    settings.write_text('fix_days:\n  high: 4\n  unknown: 10\n')
    with (inventory / 'tool.yaml').open('a') as file:
        file.write('config:\n  fix_days:\n    unknown: 3\n')
    (inventory / 'another.yaml').write_text(GOOD.replace('name: tool', 'name: another'))
    monkeypatch.setattr(nvd_client, 'fetch_cves', lambda item: [make_cve('CVE-NEW', '< 2.0.0')])
    assert main.main(['--inventory', str(inventory), '--config', str(settings)]) == 0
    bodies = [call.args[1] for call in github.create_issue.call_args_list]
    assert len(bodies) == 2
    assert '10 days after this issue was opened' in bodies[0]
    assert '3 days after this issue was opened' in bodies[1]


def test_invalid_config_fails_before_network(inventory, github, monkeypatch, capsys):
    settings = inventory / 'settings.yml'
    settings.write_text('fix_days:\n  high: false\n')
    fetch = Mock()
    monkeypatch.setattr(nvd_client, 'fetch_cves', fetch)
    assert main.main(['--inventory', str(inventory), '--config', str(settings)]) == 1
    fetch.assert_not_called()
    github.create_missing_labels.assert_not_called()
    assert 'expected an integer' in capsys.readouterr().out


def test_invalid_tool_config_fails_before_network(inventory, github):
    with (inventory / 'tool.yaml').open('a') as file:
        file.write('config:\n  fix_days:\n    typo: 3\n')
    assert main.main() == 1
    github.create_missing_labels.assert_not_called()


def test_incomplete_nvd_results_fail_run_and_check_remaining_tools(inventory, github, monkeypatch):
    (inventory / 'another.yaml').write_text(GOOD.replace('name: tool', 'name: another'))

    def search(params, config=None):
        if 'virtualMatchString' in params:
            # An empty page with outstanding results is an invalid partial scan.
            return {'vulnerabilities': [], 'resultsPerPage': 0, 'totalResults': 1}
        return {'vulnerabilities': [], 'resultsPerPage': 0, 'totalResults': 0}

    page_fetch = Mock(side_effect=search)
    monkeypatch.setattr(nvd_client, 'get_page', page_fetch)
    assert main.main() == 1
    assert page_fetch.call_count == 2
    github.create_issue.assert_not_called()


def test_jira_and_slack_without_github_deduplicate_across_runs(inventory, monkeypatch):
    from infra_vuln_watch.clients import jira_client, slack_client
    import requests

    settings = inventory / 'settings.yml'
    settings.write_text('''outputs:
  github:
    enabled: false
  jira:
    enabled: true
    base_url: https://example.atlassian.net
    project: SEC
notifications:
  slack:
    enabled: true
    state_file: receipts/slack.json
''')
    monkeypatch.delenv('GITHUB_TOKEN')
    monkeypatch.delenv('GITHUB_REPOSITORY')
    monkeypatch.setenv('JIRA_EMAIL', 'user@example.test')
    monkeypatch.setenv('JIRA_API_TOKEN', 'test-token')
    monkeypatch.setenv('SLACK_WEBHOOK_URL', 'https://hooks.slack.com/services/test/space/secret')
    monkeypatch.setattr(jira_client.time, 'sleep', lambda seconds: None)
    monkeypatch.setattr(nvd_client, 'fetch_cves', lambda item: [make_cve('CVE-2026-1234', '< 2.0.0')])
    history = []
    posts = []

    def response(data=None, body=b'', status=200):
        result = requests.Response()
        result.status_code = status
        result._content = body
        result.json = Mock(return_value=data)
        return result

    def get(url, **kwargs):
        assert url == 'https://example.atlassian.net/rest/api/3/search/jql'
        return response({'issues': history, 'isLast': True})

    def post(url, **kwargs):
        posts.append(url)
        if url.endswith('/rest/api/3/issue'):
            fields = kwargs['json']['fields']
            history.append({'fields': {'description': fields['description']}})
            return response({'key': 'SEC-1'}, status=201)
        assert url.startswith('https://hooks.slack.com/services/')
        return response(body=b'ok')

    monkeypatch.setattr(jira_client.requests, 'get', get)
    monkeypatch.setattr(slack_client.requests, 'post', post)
    args = ['--inventory', str(inventory), '--config', str(settings)]
    assert main.main(args) == 0
    assert len(posts) == 2
    assert main.main(args) == 0
    assert len(posts) == 2
    assert (inventory / 'receipts/slack.json').exists()


def test_same_product_deployments_have_independent_history_and_share_cve_search(inventory, github, monkeypatch):
    (inventory / 'tool.yaml').write_text('''name: tool
repo: o/tool
team: sre
owner: default-owner
vendor: o
product: tool
deployments:
  - id: production
    version: "1.0"
    owner: prod-owner
  - id: staging
    version: "1.0"
    owner: stage-owner
''')
    github.get_reported_ids.return_value = {'tool/production/CVE-NEW'}
    fetch = Mock(return_value=[make_cve('CVE-NEW', '< 2.0.0')])
    monkeypatch.setattr(nvd_client, 'fetch_cves', fetch)
    assert main.main() == 0
    fetch.assert_called_once()
    github.create_issue.assert_called_once()
    title, body, labels = github.create_issue.call_args.args
    assert '[STAGING]' in title
    assert 'stage-owner' in body
    assert 'tool/staging/CVE-NEW' in body
    assert 'deployment-staging' in labels


def test_deployment_versions_are_matched_independently(inventory, github, monkeypatch):
    (inventory / 'tool.yaml').write_text('''name: tool
repo: o/tool
team: sre
owner: me
vendor: o
product: tool
deployments:
  - id: production
    version: "1.0"
  - id: staging
    version: "2.0"
''')
    monkeypatch.setattr(nvd_client, 'fetch_cves', lambda item: [make_cve('CVE-NEW', '< 2.0.0')])
    assert main.main() == 0
    github.create_issue.assert_called_once()
    assert '[PROD]' in github.create_issue.call_args.args[0]


def test_global_tool_deployment_config_precedence_reaches_delivery(inventory, github, monkeypatch):
    (inventory / 'tool.yaml').write_text('''name: tool
repo: o/tool
team: sre
owner: me
vendor: o
product: tool
config:
  fix_days:
    unknown: 8
deployments:
  - id: production
    version: "1.0"
    config:
      fix_days:
        unknown: 3
  - id: staging
    version: "1.0"
''')
    settings = inventory / 'settings.yml'
    settings.write_text('fix_days:\n  unknown: 10\n')
    monkeypatch.setattr(nvd_client, 'fetch_cves', lambda item: [make_cve('CVE-NEW', '< 2.0.0')])
    assert main.main(['--inventory', str(inventory), '--config', str(settings)]) == 0
    bodies = [call.args[1] for call in github.create_issue.call_args_list]
    assert len(bodies) == 2
    assert '3 days after this issue was opened' in bodies[0]
    assert '8 days after this issue was opened' in bodies[1]
