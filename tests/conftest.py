"""Every test must use a mock. A request that reaches the real network fails the test."""

import pytest
import requests


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    def refuse(adapter, request, **kwargs):
        raise AssertionError(f'test tried to reach the network: {request.method} {request.url}')
    monkeypatch.setattr(requests.adapters.HTTPAdapter, 'send', refuse)
