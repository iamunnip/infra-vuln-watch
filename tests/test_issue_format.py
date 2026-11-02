from infra_vuln_watch import cve_details
from infra_vuln_watch import issue_format

ITEM = {"name": "openbao", "display_name": "OpenBao", "repo": "openbao/openbao", "version": "2.5.0", "owner": "iamunnip"}
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
    assert title.startswith("[LOW] [2.1] [CVE-2026-1234] OpenBao - Before 2.6.0 it leaks keys")


def test_body_has_fix_marker_and_safe_text():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    assert "Upgrade OpenBao `2.5.0` to **version 2.6.0 or later**" in body
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


def test_alert_box_matches_the_severity():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    assert body.startswith("> [!NOTE]")
    assert "**LOW, score 2.1 out of 10.**" in body


def test_unconfirmed_result_shows_a_warning():
    body = issue_format.make_body(ITEM, CVE, {"status": "unknown", "fix": None})
    assert "> [!WARNING]" in body
    assert "does not list a fixed version" in body


def test_advisories_are_listed_before_commits():
    cve = {**CVE, "references": [
        {"url": "https://github.com/o/r/commit/0f2d90c331f25d1c"},
        {"url": "https://github.com/o/r/security/advisories/GHSA-1"},
        {"url": "https://example.com/post"},
    ]}
    section = issue_format.make_references_section(cve)
    assert section.split("\n") == [
        "- [Security advisory: GHSA-1](https://redirect.github.com/o/r/security/advisories/GHSA-1)",
        "- [Commit: 0f2d90c](https://redirect.github.com/o/r/commit/0f2d90c331f25d1c)",
        "- [example.com](https://example.com/post)",
    ]


def test_odd_characters_cannot_break_a_reference_link():
    cve = {**CVE, "references": [{"url": "https://example.com/a)b [c]"}]}
    assert issue_format.make_references_section(cve) == "- [example.com](https://example.com/a%29b%20[c])"


def test_weakness_links_to_its_explanation():
    cve = {**CVE, "weaknesses": [{"description": [{"value": "CWE-208"}]}]}
    assert "[CWE-208](https://cwe.mitre.org/data/definitions/208.html)" in issue_format.make_body(ITEM, cve, RESULT)
