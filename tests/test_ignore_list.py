from datetime import date, datetime

import pytest

from infra_vuln_watch.application import scanner
from infra_vuln_watch.configuration.config import merge_config, validate_config
from infra_vuln_watch.domain import ignore_list

TODAY = date(2026, 11, 3)


def scan(value):
    return {'scan': {'ignore_cves': value}}


@pytest.mark.parametrize('value', [
    ['CVE-2026-1234'],
    ['cve-2026-1234'],
    [{'id': 'CVE-2026-1234'}],
    [{'id': 'CVE-2026-1234', 'reason': 'Not used here', 'expires': '2027-01-31'}],
    [{'id': 'CVE-2026-1234', 'expires': date(2027, 1, 31)}],
    [{'id': 'CVE-2026-1234', 'expires': datetime(2027, 1, 31, 12, 0)}],
])
def test_valid_entries(value):
    validate_config(scan(value))


@pytest.mark.parametrize('value', [
    'CVE-2026-1234',
    [12],
    ['not-a-cve'],
    ['CVE-26-1'],
    [''],
    [{'reason': 'no id'}],
    [{'id': 12}],
    [{'id': 'CVE-2026-1234', 'typo': 1}],
    [{'id': 'CVE-2026-1234', 'reason': ''}],
    [{'id': 'CVE-2026-1234', 'reason': 5}],
    [{'id': 'CVE-2026-1234', 'expires': 'soon'}],
    [{'id': 'CVE-2026-1234', 'expires': 20270131}],
])
def test_invalid_entries(value):
    with pytest.raises(ValueError):
        validate_config(scan(value))


def test_entries_with_dates_survive_merging_and_revalidation():
    merged = merge_config({}, scan([{'id': 'CVE-2026-1234', 'expires': date(2027, 1, 31)}]))
    assert merge_config({}, merged)['scan']['ignore_cves'][0]['expires'] == date(2027, 1, 31)


@pytest.mark.parametrize('entry,expected', [
    ('CVE-2026-1234', True),
    ('cve-2026-1234', True),
    ('CVE-2026-9999', False),
    ({'id': 'CVE-2026-1234', 'expires': '2026-11-03'}, True),
    ({'id': 'CVE-2026-1234', 'expires': '2026-11-02'}, False),
    ({'id': 'CVE-2026-1234', 'expires': date(2027, 1, 1)}, True),
    ({'id': 'CVE-2026-1234', 'reason': 'x'}, True),
])
def test_matching_and_expiry(entry, expected):
    assert ignore_list.is_ignored('CVE-2026-1234', [entry], TODAY) is expected


def test_describe_shows_reason_expiry_and_expired():
    lines = ignore_list.describe([
        'CVE-2026-0001',
        {'id': 'CVE-2026-0002', 'reason': 'Feature is off', 'expires': '2027-01-31'},
        {'id': 'CVE-2026-0003', 'reason': 'Old', 'expires': '2026-01-01'},
    ], TODAY)
    assert lines == [
        'Ignoring CVE-2026-0001',
        'Ignoring CVE-2026-0002 until 2027-01-31: Feature is off',
        'Ignore of CVE-2026-0003 expired on 2026-01-01, so it can be reported again',
    ]


def test_expired_ignore_reports_the_finding_again():
    item = {'name': 'tool', 'vendor': 'o', 'product': 'tool', 'version': '1.0',
            'config': merge_config({}, scan([{'id': 'CVE-2026-1234', 'expires': '2026-11-02'}]))}
    cve = {'id': 'CVE-2026-1234', 'affected': [{'affectedData': [
        {'vendor': 'o', 'product': 'tool', 'versions': [{'version': '< 2.0', 'status': 'affected'}]}]}]}
    assert len(scanner.find_problems(item, candidates=[cve], today=TODAY)) == 1
    assert scanner.find_problems(item, candidates=[cve], today=date(2026, 11, 1)) == []
