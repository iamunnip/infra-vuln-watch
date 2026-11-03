from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.clients import rate_limit


def reply(status=200, headers=None, text=''):
    response = requests.Response()
    response.status_code = status
    response.headers.update(headers or {})
    response._content = text.encode()
    return response


@pytest.fixture
def slept(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr(rate_limit.time, 'sleep', sleep)
    return sleep


@pytest.mark.parametrize('response,limited', [
    (reply(200), False),
    (reply(500), False),
    (reply(403), False),
    (reply(403, text='Resource not accessible'), False),
    (reply(429), True),
    (reply(403, {'Retry-After': '5'}), True),
    (reply(403, {'X-RateLimit-Remaining': '0'}), True),
    (reply(403, text='You have exceeded a secondary rate limit'), True),
])
def test_recognises_rate_limit_responses(response, limited):
    assert rate_limit.is_rate_limited(response) is limited


def test_waits_as_asked_then_retries_once(slept):
    request = Mock(side_effect=[reply(429, {'Retry-After': '7'}), reply(201)])
    assert rate_limit.send(request, 60).status_code == 201
    slept.assert_called_once_with(7)
    assert request.call_count == 2


def test_stops_if_still_limited_after_waiting(slept):
    request = Mock(return_value=reply(429, {'Retry-After': '1'}))
    with pytest.raises(rate_limit.RateLimited):
        rate_limit.send(request, 60)
    assert request.call_count == 2


def test_does_not_wait_longer_than_the_limit(slept):
    request = Mock(return_value=reply(429, {'Retry-After': '3600'}))
    with pytest.raises(rate_limit.RateLimited):
        rate_limit.send(request, 120)
    slept.assert_not_called()
    assert request.call_count == 1


def test_reset_time_is_used_when_there_is_no_retry_after(monkeypatch):
    monkeypatch.setattr(rate_limit.time, 'time', lambda: 1000)
    assert rate_limit.wait_seconds(reply(403, {'X-RateLimit-Reset': '1030'})) == 30


@pytest.mark.parametrize('headers', [{}, {'Retry-After': 'Wed, 21 Oct 2026 07:28:00 GMT'}])
def test_unreadable_wait_uses_the_default(headers):
    assert rate_limit.wait_seconds(reply(429, headers)) == rate_limit.DEFAULT_WAIT_SECONDS


def test_other_responses_pass_through_unchanged(slept):
    response = reply(500)
    assert rate_limit.send(Mock(return_value=response), 60) is response
    slept.assert_not_called()
