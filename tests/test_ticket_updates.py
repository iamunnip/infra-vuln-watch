from datetime import date

from infra_vuln_watch.application.ticket_updates import plan_update

TODAY = date(2026, 11, 10)
HIGH = {'severity': 'high', 'score': '7.5'}


def record(labels=('vuln-watch', 'severity-high'), title='[HIGH] [7.5] CVE-1 tool - x', fix_by=date(2026, 12, 1)):
    return {'ref': 1, 'title': title, 'labels': list(labels), 'fix_by': fix_by}


def test_nothing_changed_means_no_update():
    assert plan_update(record(), TODAY, '1.0', score=HIGH, status='affected', new_title='new') is None


def test_joining_kev_adds_the_label_and_a_comment_once():
    plan = plan_update(record(), TODAY, '1.0', score=HIGH, status='affected', known_exploited=True)
    assert plan['add_labels'] == ['known-exploited']
    assert 'CISA KEV' in plan['comment']
    done = record(labels=('severity-high', 'known-exploited'))
    assert plan_update(done, TODAY, '1.0', score=HIGH, status='affected', known_exploited=True) is None


def test_missed_fix_date_adds_overdue_once():
    late = record(fix_by=date(2026, 11, 9))
    plan = plan_update(late, TODAY, '1.0')
    assert plan['add_labels'] == ['overdue']
    assert '2026-11-09' in plan['comment']
    assert plan_update(record(labels=('overdue',), fix_by=date(2026, 11, 9)), TODAY, '1.0') is None


def test_fix_date_today_is_not_overdue():
    assert plan_update(record(fix_by=TODAY), TODAY, '1.0') is None


def test_no_deadline_is_never_overdue():
    assert plan_update(record(fix_by=None), TODAY, '1.0') is None


def test_changed_severity_replaces_the_label_and_title():
    plan = plan_update(record(), TODAY, '1.0', score={'severity': 'critical', 'score': '9.8'},
                       status='affected', new_title='[CRITICAL] [9.8] new')
    assert plan['add_labels'] == ['severity-critical']
    assert plan['remove_labels'] == ['severity-high']
    assert plan['title'] == '[CRITICAL] [9.8] new'
    assert '9.8' in plan['comment']


def test_changed_score_within_a_severity_updates_only_the_title():
    plan = plan_update(record(), TODAY, '1.0', score={'severity': 'high', 'score': '8.1'},
                       status='affected', new_title='new')
    assert plan['title'] == 'new'
    assert plan['add_labels'] == [] and plan['remove_labels'] == []


def test_upgrade_is_flagged_but_nothing_closes_the_ticket():
    plan = plan_update(record(), TODAY, '2.0', score=HIGH, status='not_affected')
    assert plan['add_labels'] == ['no-longer-affected']
    assert '`2.0`' in plan['comment']
    assert set(plan) == {'add_labels', 'remove_labels', 'title', 'comment'}


def test_resolved_ticket_is_not_marked_overdue():
    plan = plan_update(record(fix_by=date(2026, 1, 1)), TODAY, '2.0', score=HIGH, status='not_affected')
    assert 'overdue' not in plan['add_labels']


def test_downgrade_removes_the_resolved_label():
    plan = plan_update(record(labels=('severity-high', 'no-longer-affected')), TODAY, '1.0', score=HIGH, status='affected')
    assert plan['remove_labels'] == ['no-longer-affected']
    assert 'affected again' in plan['comment']


def test_cve_missing_from_the_scan_only_checks_the_date():
    assert plan_update(record(), TODAY, '1.0') is None
