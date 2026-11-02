from unittest.mock import Mock

import pytest
import requests

from infra_vuln_watch import github_client
from infra_vuln_watch import main
from infra_vuln_watch import nvd_client

GOOD = 'name: tool\nrepo: o/tool\nversion: "1.0.0"\nowner: me\nvendor: o\nproduct: tool\n'


def make_cve(cve_id, version_text, status="Analyzed"):
    data = {"vendor": "o", "product": "tool", "versions": [{"version": version_text, "status": "affected"}]}
    return {"id": cve_id, "vulnStatus": status, "affected": [{"affectedData": [data]}]}


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    (tmp_path / "tool.yaml").write_text(GOOD)
    monkeypatch.setattr("sys.argv", ["main.py", "--inventory", str(tmp_path)])
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
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
    assert "cve-new" in titles(github)[0]


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
    assert "cve-new" in capsys.readouterr().out


def test_missing_token_is_an_error(inventory, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN")
    assert main.main() == 1


def test_bad_inventory_is_a_clean_error(inventory, capsys):
    (inventory / "tool.yaml").write_text("name: tool\n")
    assert main.main() == 1
    assert "Inventory problem" in capsys.readouterr().out


def test_github_down_at_start_is_a_clean_error(inventory, github):
    github.create_missing_labels.side_effect = requests.RequestException("down")
    assert main.main() == 1
