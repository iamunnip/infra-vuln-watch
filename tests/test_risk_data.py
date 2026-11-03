from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch.clients import risk_data
from infra_vuln_watch.configuration.config import DEFAULT_CONFIG
from infra_vuln_watch.domain import cve_details


def reply(data=None, status=200):
    response = requests.Response()
    response.status_code = status
    response.json = Mock(return_value=data)
    return response


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    monkeypatch.setattr(risk_data.time, "sleep", lambda seconds: None)


def test_epss_scores_are_read(monkeypatch):
    data = {"data": [{"cve": "CVE-1", "epss": "0.00629", "percentile": "0.50131"}]}
    monkeypatch.setattr(risk_data.requests, "get", Mock(return_value=reply(data)))
    assert risk_data.fetch_epss(["CVE-1"]) == {"CVE-1": {"score": 0.00629, "percentile": 0.50131}}


def test_epss_asks_in_batches(monkeypatch):
    fake_get = Mock(return_value=reply({"data": []}))
    monkeypatch.setattr(risk_data.requests, "get", fake_get)
    risk_data.fetch_epss([f"CVE-{number}" for number in range(150)])
    assert fake_get.call_count == 2
    assert len(fake_get.call_args_list[0].kwargs["params"]["cve"].split(",")) == 100


def test_nothing_to_ask_means_no_request(monkeypatch):
    fake_get = Mock()
    monkeypatch.setattr(risk_data.requests, "get", fake_get)
    assert risk_data.fetch_epss([]) == {}
    fake_get.assert_not_called()


def test_epss_down_returns_none_after_retries(monkeypatch):
    fake_get = Mock(return_value=reply(status=503))
    monkeypatch.setattr(risk_data.requests, "get", fake_get)
    assert risk_data.fetch_epss(["CVE-1"]) is None
    assert fake_get.call_count == DEFAULT_CONFIG["sources"]["epss"]["max_attempts"]


def test_retry_can_succeed(monkeypatch):
    fake_get = Mock(side_effect=[requests.ConnectionError("down"), reply({"data": []})])
    monkeypatch.setattr(risk_data.requests, "get", fake_get)
    assert risk_data.fetch_epss(["CVE-1"]) == {}


def test_unexpected_epss_data_returns_none(monkeypatch):
    monkeypatch.setattr(risk_data.requests, "get", Mock(return_value=reply({"oops": 1})))
    assert risk_data.fetch_epss(["CVE-1"]) is None


def test_kev_is_read(monkeypatch):
    entry = {"cveID": "CVE-1", "dateAdded": "2026-01-02", "dueDate": "2026-01-23", "requiredAction": "Patch", "knownRansomwareCampaignUse": "Known"}
    monkeypatch.setattr(risk_data.requests, "get", Mock(return_value=reply({"vulnerabilities": [entry]})))
    assert risk_data.fetch_kev()["CVE-1"]["ransomware"] == "Known"


def test_kev_down_returns_none(monkeypatch):
    monkeypatch.setattr(risk_data.requests, "get", Mock(return_value=reply(status=500)))
    assert risk_data.fetch_kev() is None


def test_nvd_copy_is_used_when_the_cisa_list_is_down():
    cve = {"id": "CVE-1", "cisaExploitAdd": "2026-01-02", "cisaActionDue": "2026-01-23"}
    assert cve_details.find_kev_entry(cve, None)["date_added"] == "2026-01-02"


def test_not_listed_anywhere():
    assert cve_details.find_kev_entry({"id": "CVE-1"}, {}) is None


def test_disabled_sources_make_no_requests(monkeypatch):
    from infra_vuln_watch.configuration.config import merge_config
    config = merge_config({}, {'sources': {'epss': {'enabled': False}, 'kev': {'enabled': False}}})
    get = Mock()
    monkeypatch.setattr(risk_data.requests, 'get', get)
    assert risk_data.fetch_epss(['CVE-1'], config=config['sources']['epss']) is None
    assert risk_data.fetch_kev(config=config['sources']['kev']) is None
    get.assert_not_called()


def test_nvd_kev_fallback_can_be_disabled():
    assert cve_details.find_kev_entry({'id': 'CVE-1', 'cisaExploitAdd': '2026-01-02'}, None, allow_nvd=False) is None
