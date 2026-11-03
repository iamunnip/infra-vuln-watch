"""Wait once when a service says it is rate limiting us, then stop asking."""

import time

import requests

# GitHub asks for at least a minute when a limit response gives no time to wait.
DEFAULT_WAIT_SECONDS = 60


class RateLimited(requests.RequestException):
    """The service is still limiting us, so more requests this run would only make it worse."""


def is_rate_limited(response):
    if response.status_code == 429:
        return True
    if response.status_code != 403:
        return False
    headers = response.headers
    return ('Retry-After' in headers or headers.get('X-RateLimit-Remaining') == '0'
            or 'rate limit' in response.text.lower())


def wait_seconds(response):
    """Return how long the service asked us to wait."""
    headers = response.headers
    try:
        return max(0, int(headers['Retry-After']))
    except (KeyError, ValueError):
        pass
    try:
        return max(0, int(headers['X-RateLimit-Reset']) - int(time.time()))
    except (KeyError, ValueError):
        return DEFAULT_WAIT_SECONDS


def send(request, max_wait):
    """Call request(), and retry once if asked to wait no longer than max_wait.

    A rate limited request was not carried out, so repeating a write cannot duplicate it.
    """
    response = request()
    if not is_rate_limited(response):
        return response
    wait = wait_seconds(response)
    if wait > max_wait:
        raise RateLimited(f'rate limited; asked to wait {wait} seconds')
    time.sleep(wait)
    response = request()
    if is_rate_limited(response):
        raise RateLimited('still rate limited after waiting')
    return response
