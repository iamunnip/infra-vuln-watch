from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.clients import jira_client
from infra_vuln_watch.configuration.config import merge_config


def response(data, status=200):
    reply = requests.Response()
    reply.status_code = status
    reply.json = Mock(return_value=data)
    return reply


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(jira_client.time, 'sleep', lambda seconds: None)
    config = merge_config({}, {'outputs': {'jira': {
        'enabled': True, 'base_url': 'https://example.atlassian.net', 'project': 'SEC',
        'fields': {'priority': {'name': 'High'}},
    }}})['outputs']['jira']
    return jira_client.JiraClient('user@example.test', 'secret', config)


def test_paginates_history_without_excluding_closed_tickets(monkeypatch, client):
    description = jira_client.description_document('details\n<!-- vuln-watch-id: tool/CVE-2026-1234 -->')
    get = Mock(side_effect=[
        response({'issues': [{'fields': {'description': description}}], 'isLast': False, 'nextPageToken': 'next'}),
        response({'issues': [], 'isLast': True}),
    ])
    monkeypatch.setattr(jira_client.requests, 'get', get)
    assert client.get_reported_ids() == {'tool/CVE-2026-1234'}
    assert get.call_args.kwargs['params']['nextPageToken'] == 'next'
    jql = get.call_args.kwargs['params']['jql']
    assert 'SEC' in jql and 'vuln-watch' in jql
    assert 'status' not in jql


@pytest.mark.parametrize('page', [{}, {'issues': [], 'isLast': False},
    {'issues': None, 'isLast': True}])
def test_bad_history_fails_instead_of_allowing_duplicate_creation(monkeypatch, client, page):
    monkeypatch.setattr(jira_client.requests, 'get', Mock(return_value=response(page)))
    with pytest.raises(requests.RequestException):
        client.get_reported_ids()


def test_repeated_pagination_token_fails(monkeypatch, client):
    get = Mock(return_value=response({'issues': [], 'isLast': False, 'nextPageToken': 'same'}))
    monkeypatch.setattr(jira_client.requests, 'get', get)
    with pytest.raises(requests.RequestException):
        client.get_reported_ids()
    assert get.call_count == 2


def test_creates_cloud_ticket_with_adf_and_custom_fields(monkeypatch, client):
    post = Mock(return_value=response({'key': 'SEC-42'}, 201))
    monkeypatch.setattr(jira_client.requests, 'post', post)
    body = 'Untrusted @user and <markup>\n\n<!-- vuln-watch-id: tool/CVE-2026-1234 -->'
    assert client.create_issue('x' * 300, body, ['vuln-watch']) == 'https://example.atlassian.net/browse/SEC-42'
    request = post.call_args.kwargs
    fields = request['json']['fields']
    assert len(fields['summary']) == 255
    assert fields['project'] == {'key': 'SEC'}
    assert fields['priority'] == {'name': 'High'}
    assert fields['description']['type'] == 'doc'
    assert '<!-- vuln-watch-id: tool/CVE-2026-1234 -->' in jira_client.adf_text(fields['description'])
    assert request['auth'] == ('user@example.test', 'secret')
    assert post.call_args.args[0].endswith('/rest/api/3/issue')


def test_create_failure_is_not_automatically_retried(monkeypatch, client):
    post = Mock(return_value=response({}, 403))
    monkeypatch.setattr(jira_client.requests, 'post', post)
    with pytest.raises(requests.RequestException):
        client.create_issue('title', 'body', [])
    assert post.call_count == 1
