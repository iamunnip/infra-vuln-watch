from datetime import date

import pytest

from infra_vuln_watch.domain import cve_details
from infra_vuln_watch.reporting import issue_format

ITEM = {"name": "openbao", "display_name": "OpenBao", "repo": "openbao/openbao", "version": "2.5.0", "team": "sre", "owner": "iamunnip"}
CVE = {
    "id": "CVE-2026-1234",
    "descriptions": [{"lang": "en", "value": "OpenBao is an open source tool. Before 2.6.0 it leaks keys to @someone. Fixed later."}],
    "metrics": {
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 2.1, "baseSeverity": "LOW", "vectorString": "CVSS:3.1/AV:N", "attackVector": "ADJACENT_NETWORK", "confidentialityImpact": "HIGH"}}],
    },
    "references": [{"url": "https://github.com/openbao/openbao/security/advisories/GHSA-1"}],
}
AFFECTED_VERSIONS = [{"text": "< 2.6.0", "includes_installed": True}]
RESULT = {"status": "affected", "fix": "version 2.6.0 or later", "affected_versions": AFFECTED_VERSIONS}


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


@pytest.mark.parametrize(
    "score, severity",
    [
        (0.0, "none"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_severity_comes_from_the_score(score, severity):
    assert cve_details.severity_from_score(score) == severity


def test_old_cvss_2_labels_do_not_override_the_scale():
    # CVSS 2 has no "critical", so NVD would call this score "high".
    cve = {"metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 9.5}}]}}
    assert cve_details.get_score(cve)["severity"] == "critical"


def test_no_score():
    assert cve_details.get_score({})["score"] == "n/a"


def test_alert_box_matches_the_severity():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    assert body.startswith("> [!NOTE]")
    assert "**LOW, score 2.1 out of 10.**" in body


def test_unconfirmed_result_shows_a_warning():
    body = issue_format.make_body(ITEM, CVE, {"status": "unknown", "fix": None, "affected_versions": []})
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


def test_sections_are_in_the_agreed_order():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    order = ["## What is the problem?", "## Details", "## How to fix it", "## Learn more"]
    assert [body.index(heading) for heading in order] == sorted(body.index(heading) for heading in order)


def test_details_show_versions_attack_and_impact():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    assert "- `< 2.6.0` **(includes your version)**" in body
    assert "| Attack from | Adjacent network |" in body
    assert "| Confidentiality impact | High |" in body
    assert "CVSS 3.1: 2.1 (Low)" in body


def test_cvss_4_impact_names_are_understood():
    data = {"baseScore": 9.2, "vulnIntegrityImpact": "HIGH"}
    cve = {"metrics": {"cvssMetricV40": [{"cvssData": data}]}}
    assert cve_details.get_score(cve)["impact"] == {"Integrity impact": "High"}


def test_exploit_status_reads_ssvc():
    options = [{"exploitation": "none"}, {"automatable": "no"}, {"technicalImpact": "total"}]
    cve = {"metrics": {"ssvcV203": [{"ssvcData": {"options": options, "timestamp": "2026-09-23T19:13:35Z"}}]}}
    assert cve_details.get_exploit_status(cve) == {
        "Exploitation seen": "None",
        "Can be automated": "No",
        "Technical impact": "Total",
        "Assessed on": "2026-09-23",
    }


def test_reporter_email_cannot_mention_anyone():
    body = issue_format.make_body(ITEM, {**CVE, "sourceIdentifier": "a@someone"}, RESULT)
    assert "a@someone" not in body


def test_multiple_branches_get_a_warning_and_advisory_gets_a_workaround_link():
    versions = AFFECTED_VERSIONS + [{"text": ">= 2.7.0 and < 2.7.1", "includes_installed": False}]
    body = issue_format.make_body(ITEM, CVE, {**RESULT, "affected_versions": versions})
    assert "more than one release branch" in body
    assert "for a workaround" in body
    assert "more than one release branch" not in issue_format.make_body(ITEM, CVE, RESULT)


def test_owner_is_the_last_row_of_the_tool_table_with_team_above_it():
    body = issue_format.make_body(ITEM, CVE, RESULT)
    table = body.split("### Affected tool")[1].split("###")[0].strip().split("\n")
    assert table[-2:] == ["| Team | sre |", "| Owner | `iamunnip` |"]


def test_deadline_is_shown_in_the_box_and_severity_table():
    body = issue_format.make_body(ITEM, CVE, RESULT, opened_on=date(2026, 11, 2))
    expected = "2026-11-23 (21 days after this issue was opened)"
    assert f"> **Fix by:** {expected}" in body
    assert f"| Fix by | {expected} |" in body


def test_cve_without_a_score_has_no_deadline():
    cve = {**CVE, "metrics": {}}
    assert "No deadline for this severity" in issue_format.make_body(ITEM, cve, RESULT)


def test_long_link_text_is_shortened():
    url = "https://example.com/advisories/" + "a" * 100
    assert issue_format.describe_reference(url)[1] == "Security advisory: " + "a" * 37 + "..."


KEV_ENTRY = {"date_added": "2026-01-02", "due_date": "2026-01-23", "required_action": "Patch | now", "ransomware": "Known"}


def test_risk_summary_shows_all_three_measures():
    risk = {"epss": {"CVE-2026-1234": {"score": 0.0063, "percentile": 0.5013}}, "kev": {}}
    body = issue_format.make_body(ITEM, CVE, RESULT, risk)
    assert "| CVSS | 2.1 (Low) |" in body
    assert "| EPSS | 0.63% chance, higher than 50% of all CVEs |" in body
    assert "| CISA KEV | Not listed |" in body
    assert "CISA KEV details" not in body


def test_failed_lookup_is_not_shown_as_a_clean_result():
    body = issue_format.make_body(ITEM, CVE, RESULT, {"epss": None, "kev": None})
    assert "| EPSS | Could not check |" in body
    assert "| CISA KEV | Could not check |" in body


def test_cve_without_an_epss_score_says_so():
    assert "| EPSS | No score yet |" in issue_format.make_body(ITEM, CVE, RESULT, {"epss": {}, "kev": {}})


def test_known_exploited_cve_gets_the_strongest_box_and_details():
    body = issue_format.make_body(ITEM, CVE, RESULT, {"epss": {}, "kev": {"CVE-2026-1234": KEV_ENTRY}})
    assert body.startswith("> [!CAUTION]")
    assert "**Known to be exploited in the wild**" in body
    assert "| CISA KEV | **Yes**, added 2026-01-02 |" in body
    assert "| CISA fix deadline | 2026-01-23 |" in body
    assert "Patch \\| now" in body


def test_very_high_epss_does_not_round_up_to_certain():
    risk = {"epss": {"CVE-2026-1234": {"score": 0.99999, "percentile": 1.0}}, "kev": {}}
    assert "99.99% chance, higher than 99% of all CVEs" in issue_format.make_body(ITEM, CVE, RESULT, risk)


def test_known_exploited_low_score_gets_the_critical_deadline():
    risk = {"epss": {}, "kev": {"CVE-2026-1234": KEV_ENTRY}}
    body = issue_format.make_body(ITEM, CVE, RESULT, risk, opened_on=date(2026, 11, 2))
    assert "> **Fix by:** 2026-11-04 (2 days after this issue was opened)" in body


def test_disabled_risk_sources_are_distinguished_from_outages():
    assert issue_format.describe_epss({'id': 'CVE-X'}, None, enabled=False) == 'Disabled'
    assert issue_format.describe_kev(None, None, enabled=False) == 'Catalog disabled'


def test_deployment_finding_shows_scope_ownership_and_stable_marker():
    from infra_vuln_watch.domain.identity import inventory_id
    item = {'name': 'openbao', 'display_name': 'OpenBao', 'repo': 'openbao/openbao',
            'version': '2.5.5', 'team': 'platform', 'owner': 'production-owner',
            'deployment_id': 'prod-eu', 'environment': 'production'}
    cve = {'id': 'CVE-2026-1234'}
    result = {'status': 'affected', 'fix': None, 'affected_versions': []}
    assert inventory_id(item) == 'openbao/prod-eu'
    assert 'OpenBao [production/prod-eu]' in issue_format.make_title(item, cve)
    body = issue_format.make_body(item, cve, result)
    assert '| Deployment | prod-eu |' in body
    assert '| Environment | production |' in body
    assert 'production-owner' in body
    assert 'Update `version` for deployment `prod-eu`' in body
    assert '<!-- vuln-watch-id: openbao/prod-eu/CVE-2026-1234 -->' in body
    changed_version = {**item, 'version': '2.6.4'}
    assert issue_format.issue_marker(changed_version, cve) == issue_format.issue_marker(item, cve)
