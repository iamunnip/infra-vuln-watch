from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.clients import github_client


def reply(data=None, status=200):
    response = requests.Response()
    response.status_code = status
    response.json = Mock(return_value=data)
    return response


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(github_client.time, "sleep", lambda seconds: None)
    return github_client.GitHubClient("token", "owner/repo")


def test_reads_every_page(monkeypatch, client):
    first_page = [{"body": f"<!-- vuln-watch-id: a/CVE-{number} -->"} for number in range(100)]
    second_page = [{"body": "<!-- vuln-watch-id: a/CVE-LAST -->"}, {"body": None}]
    fake_get = Mock(side_effect=[reply(first_page), reply(second_page)])
    monkeypatch.setattr(github_client.requests, "get", fake_get)

    reported = client.get_reported_ids()
    assert len(reported) == 101
    assert "a/CVE-LAST" in reported


def test_only_trusts_issues_with_our_label_and_includes_closed(monkeypatch, client):
    fake_get = Mock(return_value=reply([]))
    monkeypatch.setattr(github_client.requests, "get", fake_get)

    client.get_reported_ids()
    params = fake_get.call_args.kwargs["params"]
    assert params["labels"] == "vuln-watch"
    assert params["state"] == "all"


def test_only_missing_labels_are_created(monkeypatch, client):
    existing = [{"name": "vuln-watch"}, {"name": "severity-high"}]
    monkeypatch.setattr(github_client.requests, "get", Mock(return_value=reply(existing)))
    fake_post = Mock(return_value=reply({}))
    monkeypatch.setattr(github_client.requests, "post", fake_post)

    client.create_missing_labels(["openbao"])
    created = [call.kwargs["json"]["name"] for call in fake_post.call_args_list]
    assert "needs-review" in created
    assert "severity-low" in created
    assert "tool-openbao" in created
    assert "vuln-watch" not in created
    assert "severity-high" not in created


def test_create_issue_sends_title_body_and_labels(monkeypatch, client):
    fake_post = Mock(return_value=reply({"html_url": "https://example.test/1"}))
    monkeypatch.setattr(github_client.requests, "post", fake_post)

    assert client.create_issue("x" * 300, "body", ["vuln-watch"]) == "https://example.test/1"
    sent = fake_post.call_args.kwargs
    assert fake_post.call_args.args[0].endswith("/repos/owner/repo/issues")
    assert len(sent["json"]["title"]) == 256
    assert sent["json"]["labels"] == ["vuln-watch"]
    assert sent["headers"]["Authorization"] == "Bearer token"


def test_github_errors_are_raised(monkeypatch, client):
    monkeypatch.setattr(github_client.requests, "post", Mock(return_value=reply({}, status=403)))
    with pytest.raises(requests.HTTPError):
        client.create_issue("title", "body", [])


def test_invalid_history_page_fails_instead_of_returning_empty_history(monkeypatch, client):
    monkeypatch.setattr(github_client.requests, 'get', Mock(return_value=reply({})))
    with pytest.raises(requests.RequestException, match='invalid list response'):
        client.get_reported_ids()


def test_labels_differing_only_by_case_are_one_label(monkeypatch, client):
    existing = [{"name": "VULN-WATCH"}]
    monkeypatch.setattr(github_client.requests, "get", Mock(return_value=reply(existing)))
    post = Mock(return_value=reply({}, status=201))
    monkeypatch.setattr(github_client.requests, "post", post)

    client.create_missing_labels(["tool"], deployment_ids=["Prod", "prod"])

    created = [call.kwargs["json"]["name"] for call in post.call_args_list]
    assert "vuln-watch" not in created
    assert [name for name in created if name.casefold() == "deployment-prod"] == ["deployment-Prod"]


def test_remembers_the_address_of_each_reported_issue(monkeypatch, client):
    issues = [{"body": "<!-- vuln-watch-id: a/CVE-1 -->", "html_url": "https://github.com/o/r/issues/1"}]
    monkeypatch.setattr(github_client.requests, "get", Mock(return_value=reply(issues)))
    client.get_reported_ids()
    assert client.reported_links == {"a/CVE-1": "https://github.com/o/r/issues/1"}
