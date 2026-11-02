from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch import nvd_client

ITEM = {"vendor": "openbao", "product": "openbao", "keyword": "openbao"}


def reply(status=200, data=None):
    """Build a fake NVD response."""
    response = requests.Response()
    response.status_code = status
    response.json = Mock(return_value=data)
    return response


def page(ids, total=None):
    cves = [{"cve": {"id": cve_id}} for cve_id in ids]
    return {"vulnerabilities": cves, "resultsPerPage": len(ids), "totalResults": total if total is not None else len(ids)}


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    monkeypatch.setattr(nvd_client.time, "sleep", lambda seconds: None)
    monkeypatch.delenv("NVD_API_KEY", raising=False)


def test_reads_every_page(monkeypatch):
    fake_get = Mock(side_effect=[reply(data=page(["A", "B"], total=3)), reply(data=page(["C"], total=3))])
    monkeypatch.setattr(nvd_client.requests, "get", fake_get)

    assert [cve["id"] for cve in nvd_client.search({"keywordSearch": "x"})] == ["A", "B", "C"]
    assert fake_get.call_args_list[1].kwargs["params"]["startIndex"] == 2


def test_no_results(monkeypatch):
    monkeypatch.setattr(nvd_client.requests, "get", Mock(return_value=reply(data=page([]))))
    assert nvd_client.search({"keywordSearch": "x"}) == []


def test_retries_when_nvd_is_busy(monkeypatch):
    fake_get = Mock(side_effect=[reply(503), requests.ConnectionError("down"), reply(data=page(["A"]))])
    monkeypatch.setattr(nvd_client.requests, "get", fake_get)

    assert len(nvd_client.search({"keywordSearch": "x"})) == 1
    assert fake_get.call_count == 3


def test_gives_up_with_an_error_instead_of_returning_nothing(monkeypatch):
    fake_get = Mock(return_value=reply(503))
    monkeypatch.setattr(nvd_client.requests, "get", fake_get)

    with pytest.raises(requests.RequestException):
        nvd_client.search({"keywordSearch": "x"})
    assert fake_get.call_count == nvd_client.MAX_ATTEMPTS


def test_bad_request_is_not_retried(monkeypatch):
    fake_get = Mock(return_value=reply(404))
    monkeypatch.setattr(nvd_client.requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        nvd_client.search({"keywordSearch": "x"})
    assert fake_get.call_count == 1


def test_api_key_is_sent_when_set(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "secret")
    fake_get = Mock(return_value=reply(data=page([])))
    monkeypatch.setattr(nvd_client.requests, "get", fake_get)

    nvd_client.search({"keywordSearch": "x"})
    assert fake_get.call_args.kwargs["headers"] == {"apiKey": "secret"}


def test_both_searches_are_merged_without_duplicates(monkeypatch):
    fake_get = Mock(side_effect=[reply(data=page(["A", "B"])), reply(data=page(["B", "C"]))])
    monkeypatch.setattr(nvd_client.requests, "get", fake_get)

    assert sorted(cve["id"] for cve in nvd_client.fetch_cves(ITEM)) == ["A", "B", "C"]
