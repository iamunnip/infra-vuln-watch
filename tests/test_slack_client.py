import json
from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.clients import slack_client
from infra_vuln_watch.configuration.config import merge_config
from infra_vuln_watch.persistence.state import DeliveryState

WEBHOOK = 'https://hooks.slack.com/services/test/workspace/secret'


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setattr(slack_client.time, 'sleep', lambda seconds: None)
    return merge_config({}, {'notifications': {'slack': {
        'enabled': True, 'state_file': str(tmp_path / 'state.json'),
    }}})['notifications']['slack']


def ok():
    response = requests.Response()
    response.status_code = 200
    response._content = b'ok'
    return response


def test_receipts_persist_without_webhook_secret(monkeypatch, settings):
    post = Mock(return_value=ok())
    monkeypatch.setattr(slack_client.requests, 'post', post)
    client = slack_client.SlackClient(WEBHOOK, settings)
    marker = 'tool/CVE-2026-1234'
    assert client.needs_delivery(marker)
    client.send(marker, 'CVE with <!channel> text', ['https://nvd.nist.gov/'])
    assert not slack_client.SlackClient(WEBHOOK, settings).needs_delivery(marker)
    saved = json.loads(open(settings['state_file']).read())
    assert saved['version'] == 1
    assert WEBHOOK not in json.dumps(saved)
    payload = post.call_args.kwargs['json']
    assert payload['blocks'][0]['text']['type'] == 'plain_text'
    assert '<!channel>' not in payload['text']
    assert post.call_args.kwargs['allow_redirects'] is False


def test_failure_remains_pending_and_redacts_secret(monkeypatch, settings):
    monkeypatch.setattr(slack_client.requests, 'post', Mock(side_effect=requests.ConnectionError(WEBHOOK)))
    client = slack_client.SlackClient(WEBHOOK, settings)
    with pytest.raises(requests.RequestException) as error:
        client.send('tool/CVE-2026-1234', 'title', [])
    assert WEBHOOK not in str(error.value)
    assert client.needs_delivery('tool/CVE-2026-1234')


def test_repeat_mode_needs_no_state_file(monkeypatch, settings):
    settings['repeat'] = True
    monkeypatch.setattr(slack_client.requests, 'post', Mock(return_value=ok()))
    client = slack_client.SlackClient(WEBHOOK, settings)
    client.send('tool/cve', 'title', [])
    assert client.needs_delivery('tool/cve')
    from pathlib import Path
    assert not Path(settings['state_file']).exists()


def test_receipts_do_not_suppress_another_destination(monkeypatch, settings):
    monkeypatch.setattr(slack_client.requests, 'post', Mock(return_value=ok()))
    slack_client.SlackClient(WEBHOOK, settings).send('tool/cve', 'title', [])
    other = slack_client.SlackClient(WEBHOOK + '-other', settings)
    assert other.needs_delivery('tool/cve')


@pytest.mark.parametrize('url', ['http://hooks.slack.com/services/x',
    'https://example.test/services/x', 'https://hooks.slack.com/not-a-webhook'])
def test_invalid_webhook_is_rejected(settings, url):
    with pytest.raises(ValueError, match='Slack HTTPS'):
        slack_client.SlackClient(url, settings)


def test_corrupt_receipts_fail_closed(settings):
    from pathlib import Path
    Path(settings['state_file']).write_text('{broken')
    with pytest.raises(ValueError, match='delivery state'):
        DeliveryState(settings['state_file'])


def test_atomic_state_preserves_existing_receipts(tmp_path):
    path = tmp_path / 'state.json'
    state = DeliveryState(path)
    state.remember('first')
    state.remember('second')
    assert DeliveryState(path).delivered == {'first', 'second'}
    assert list(tmp_path.glob('.delivery-*')) == []
