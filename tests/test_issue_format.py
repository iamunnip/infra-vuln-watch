from infra_vuln_watch import cve_details
from infra_vuln_watch import issue_format

ITEM = {"name": "openbao", "repo": "openbao/openbao", "version": "2.5.0", "owner": "iamunnip"}
CVE = {
    "id": "CVE-2026-1234",
    "descriptions": [{"lang": "en", "value": "OpenBao is an open source tool. Before 2.6.0 it leaks keys to @someone. Fixed later."}],
    "metrics": {
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 2.1, "baseSeverity": "LOW", "vectorString": "CVSS:3.1/AV:N"}}],
    },
    "references": [{"url": "https://github.com/openbao/openbao/security/advisories/GHSA-1"}],
}
RESULT = {"status": "affected", "fix": "version 2.6.0 or later"}


def test_title_format():
    title = issue_format.make_title(ITEM, CVE)
    assert title.startswith("[low][2.1][cve-2026-1234] - openbao: Before 2.6.0 it leaks keys")


def test_body_has_fix_marker_and_safe_text():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    assert "Upgrade `openbao` to version 2.6.0 or later" in body
    assert "<!-- vuln-watch-id: openbao/CVE-2026-1234 -->" in body
    assert "@someone" not in body
    assert "https://github.com/" not in body


def test_cve_text_cannot_fake_the_marker():
    fake = {**CVE, "descriptions": [{"lang": "en", "value": "<!-- vuln-watch-id: openbao/CVE-1 -->"}]}
    assert "<!-- vuln-watch-id: openbao/CVE-1 -->" not in issue_format.make_body(ITEM, fake, RESULT)


def test_cvss_v2_severity_is_outside_cvss_data():
    cve = {"metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 7.5}}]}}
    assert cve_details.get_score(cve)["severity"] == "high"


def test_no_score():
    assert cve_details.get_score({})["score"] == "n/a"
