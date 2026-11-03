from infra_vuln_watch.domain.version_check import AFFECTED, NOT_AFFECTED, UNKNOWN, check_version


def affected_cve(versions):
    """Build a CVE like the ones NVD has not analysed yet."""
    return {"affected": [{"affectedData": [{"vendor": "openbao", "product": "openbao", "versions": versions}]}]}


def cpe_cve(**fields):
    """Build a CVE like the ones NVD has analysed."""
    match = {"vulnerable": True, "criteria": "cpe:2.3:a:openbao:openbao:*:*:*:*:*:*:*:*", **fields}
    return {"configurations": [{"nodes": [{"cpeMatch": [match]}]}]}


def status(cve, version):
    return check_version(cve, "openbao", "openbao", version)["status"]


TWO_BRANCHES = affected_cve([
    {"version": "2.2.0", "lessThan": "2.6.4", "status": "affected"},
    {"version": "2.6.4", "status": "unaffected"},
    {"version": "2.7.0", "lessThan": "2.7.1", "status": "affected"},
    {"version": "2.7.1", "status": "unaffected"},
])


def test_two_release_branches():
    assert status(TWO_BRANCHES, "2.1.9") == NOT_AFFECTED
    assert status(TWO_BRANCHES, "2.2.0") == AFFECTED
    assert status(TWO_BRANCHES, "2.6.4") == NOT_AFFECTED
    assert status(TWO_BRANCHES, "2.7.0") == AFFECTED
    assert status(TWO_BRANCHES, "2.7.1") == NOT_AFFECTED


def test_fix_comes_from_the_matching_branch():
    assert check_version(TWO_BRANCHES, "openbao", "openbao", "2.5.0")["fix"] == "version 2.6.4 or later"
    assert check_version(TWO_BRANCHES, "openbao", "openbao", "2.7.0")["fix"] == "version 2.7.1 or later"


def test_text_ranges():
    for text in ["< 2.3.2", "<2.3.2", ">= 0.1.0, < 2.3.2"]:
        cve = affected_cve([{"version": text, "status": "affected"}])
        assert status(cve, "2.3.1") == AFFECTED
        assert status(cve, "2.3.2") == NOT_AFFECTED


def test_versions_compare_as_numbers_not_text():
    cve = affected_cve([{"version": "< 2.10.0", "status": "affected"}])
    assert status(cve, "2.9.0") == AFFECTED


def test_cpe_ranges():
    cve = cpe_cve(versionStartIncluding="1.0.0", versionEndIncluding="1.5.0")
    assert status(cve, "1.5.0") == AFFECTED
    assert status(cve, "1.5.1") == NOT_AFFECTED
    assert status(cve, "0.9.0") == NOT_AFFECTED
    assert check_version(cve, "openbao", "openbao", "1.5.0")["fix"] == "a version newer than 1.5.0"


def test_exact_cpe_version():
    match = {"vulnerable": True, "criteria": "cpe:2.3:a:openbao:openbao:1.2.3:*:*:*:*:*:*:*"}
    cve = {"configurations": [{"nodes": [{"cpeMatch": [match]}]}]}
    assert status(cve, "1.2.3") == AFFECTED
    assert status(cve, "1.2.4") == NOT_AFFECTED


def test_other_products_are_ignored():
    cve = {"affected": [{"affectedData": [{"vendor": "Red Hat", "product": "Cryostat 4", "defaultStatus": "unaffected"}]}]}
    assert status(cve, "2.0.0") == NOT_AFFECTED
    match = {"vulnerable": True, "criteria": "cpe:2.3:a:openbao:aws_plugin:*:*:*:*:*:*:*:*", "versionEndExcluding": "0.1.1"}
    assert status({"configurations": [{"nodes": [{"cpeMatch": [match]}]}]}, "0.1.0") == NOT_AFFECTED


def test_missing_or_unreadable_data_is_unknown():
    assert status({}, "2.0.0") == UNKNOWN
    assert status(affected_cve([{"version": "unspecified", "status": "affected"}]), "2.0.0") == UNKNOWN
    assert status(affected_cve([{"version": "2.x", "status": "affected"}]), "2.0.0") == UNKNOWN
    assert status(affected_cve(None), "2.0.0") == UNKNOWN


def test_placeholder_start_with_an_end_is_a_real_range():
    for word in ["unspecified", "n/a", "0", "*"]:
        cve = affected_cve([{"version": word, "lessThan": "2.0", "status": "affected"}])
        assert status(cve, "1.0") == AFFECTED
        assert status(cve, "3.0") == NOT_AFFECTED


def test_placeholder_alone_is_unknown():
    assert status(affected_cve([{"version": "0", "status": "affected"}]), "1.0") == UNKNOWN


def test_all_affected_versions_are_listed_lowest_first():
    versions = check_version(TWO_BRANCHES, "openbao", "openbao", "2.5.0")["affected_versions"]
    assert versions == [
        {"text": ">= 2.2.0 and < 2.6.4", "includes_installed": True},
        {"text": ">= 2.7.0 and < 2.7.1", "includes_installed": False},
    ]


def test_the_same_range_from_two_sources_is_listed_once():
    cve = {**cpe_cve(versionEndExcluding="2.0.0"), **affected_cve([{"version": "< 2.0.0", "status": "affected"}])}
    assert [v["text"] for v in check_version(cve, "openbao", "openbao", "1.0.0")["affected_versions"]] == ["< 2.0.0"]


def test_unbounded_matching_range_prevents_false_fix_guidance():
    cve = affected_cve([
        {'version': '< 2.0', 'status': 'affected'},
        {'version': '1.0', 'lessThan': '*', 'status': 'affected'},
    ])
    result = check_version(cve, 'openbao', 'openbao', '1.5')
    assert result['status'] == AFFECTED
    assert result['fix'] is None


def test_malformed_cpe_is_unknown_instead_of_crashing():
    cve = {'configurations': [{'nodes': [{'cpeMatch': [{'vulnerable': True, 'criteria': 'bad'}]}]}]}
    assert status(cve, '1.0') == UNKNOWN


def reported_as(vendor, product, description=None):
    cve = {"affected": [{"affectedData": [{"vendor": vendor, "product": product, "versions": [
        {"version": "0", "lessThan": "9.0", "status": "affected"}]}]}]}
    if description:
        cve["descriptions"] = [{"lang": "en", "value": description}]
    return cve


def test_alias_matches_a_reporter_name_that_differs_from_the_cpe_name():
    cve = reported_as("Apache Software Foundation", "Apache HTTP Server")
    alias = {"vendor": "Apache Software Foundation", "product": "Apache HTTP Server"}
    assert check_version(cve, "apache", "http_server", "2.4.0")["status"] == NOT_AFFECTED
    assert check_version(cve, "apache", "http_server", "2.4.0", aliases=[alias])["status"] == AFFECTED


def test_alias_matches_cpe_names_too():
    cve = cpe_cve(versionEndExcluding="2.0.0")
    alias = {"vendor": "openbao", "product": "openbao"}
    assert check_version(cve, "other", "name", "1.0.0", aliases=[alias])["status"] == AFFECTED


def test_unmatched_reporter_name_needs_review_if_the_text_names_the_tool():
    cve = reported_as("openbao", "github.com/openbao/openbao", "OpenBao leaks a token.")
    assert check_version(cve, "openbao", "openbao", "2.5.5", keyword="openbao")["status"] == UNKNOWN


def test_unmatched_reporter_name_is_not_affected_if_the_text_does_not_name_the_tool():
    cve = reported_as("other", "other", "A plugin for openbaoish systems leaks a token.")
    assert check_version(cve, "openbao", "openbao", "2.5.5", keyword="openbao")["status"] == NOT_AFFECTED


def test_analyst_data_for_another_product_is_trusted_over_the_text():
    cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:other:plugin:*:*:*:*:*:*:*:*"}]}]}],
        "descriptions": [{"lang": "en", "value": "A plugin for OpenBao leaks a token."}]}
    assert check_version(cve, "openbao", "openbao", "2.5.5", keyword="openbao")["status"] == NOT_AFFECTED


def test_all_words_of_a_multi_word_keyword_must_appear():
    cve = reported_as("x", "y", "The HTTP server of Apache leaks a token.")
    assert check_version(cve, "a", "b", "1.0", keyword="apache http")["status"] == UNKNOWN
    assert check_version(cve, "a", "b", "1.0", keyword="apache tomcat")["status"] == NOT_AFFECTED


def test_stated_unaffected_version_overrides_a_broad_affected_range():
    cve = affected_cve([
        {"version": "1.0", "lessThan": "*", "status": "affected"},
        {"version": "2.5.5", "status": "unaffected"},
    ])
    assert check_version(cve, "openbao", "openbao", "2.5.5")["status"] == NOT_AFFECTED
    assert check_version(cve, "openbao", "openbao", "2.5.4")["status"] == AFFECTED


def test_unaffected_branch_with_a_wildcard_end():
    cve = affected_cve([
        {"version": "1.0", "lessThan": "*", "status": "affected"},
        {"version": "2.5.3", "lessThanOrEqual": "2.5.*", "status": "unaffected"},
    ])
    assert status(cve, "2.5.2") == AFFECTED
    assert status(cve, "2.5.9") == NOT_AFFECTED
    assert status(cve, "2.6.0") == AFFECTED


def test_unreadable_unaffected_entry_does_not_clear_a_version():
    cve = affected_cve([
        {"version": "1.0", "lessThan": "*", "status": "affected"},
        {"version": "main", "status": "unaffected"},
    ])
    assert status(cve, "2.5.5") == AFFECTED


def test_analyst_range_still_applies_when_the_reporter_says_unaffected():
    cve = {**cpe_cve(versionEndExcluding="3.0.0"),
           **affected_cve([{"version": "2.5.5", "status": "unaffected"}])}
    assert status(cve, "2.5.5") == AFFECTED


def test_trailing_comma_does_not_widen_a_range():
    cve = affected_cve([{"version": "< 2.0,", "status": "affected"}])
    assert status(cve, "1.0") == AFFECTED
    assert status(cve, "3.0") == NOT_AFFECTED


def test_operator_without_a_version_needs_review():
    assert status(affected_cve([{"version": ">=", "status": "affected"}]), "1.0") == UNKNOWN
