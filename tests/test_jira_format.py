from datetime import date

from infra_vuln_watch.clients.jira_client import adf_text
from infra_vuln_watch.domain.fix_deadline import read_fix_date
from infra_vuln_watch.domain.identity import MARKER_PATTERN
from infra_vuln_watch.reporting import issue_format
from infra_vuln_watch.reporting.jira_format import inline, markdown_to_adf

ITEM = {'name': 'openbao', 'display_name': 'OpenBao', 'repo': 'openbao/openbao', 'version': '2.5.0',
        'team': 'sre', 'owner': 'me'}
CVE = {'id': 'CVE-2026-1234',
       'descriptions': [{'lang': 'en', 'value': 'It leaks **keys** to @someone with <!-- vuln-watch-id: x/CVE-1 -->.'}],
       'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 7.5, 'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N'}}]},
       'references': [{'url': 'https://github.com/o/r/security/advisories/GHSA-1'}]}
RESULT = {'status': 'affected', 'fix': 'version 2.6.0 or later',
          'affected_versions': [{'text': '< 2.6.0', 'includes_installed': True}]}


def types(document):
    return [node['type'] for node in document['content']]


def walk(node):
    yield node
    for child in node.get('content', []):
        yield from walk(child)


def finding():
    body = issue_format.make_body(ITEM, CVE, RESULT, {'epss': {}, 'kev': {}}, opened_on=date(2026, 11, 3))
    return body, markdown_to_adf(body)


def test_a_finding_becomes_rich_blocks():
    _, document = finding()
    kinds = types(document)
    for kind in ('panel', 'heading', 'table', 'orderedList', 'bulletList'):
        assert kind in kinds
    assert document['content'][0]['attrs']['panelType'] == 'error'


def test_no_raw_markdown_is_left_in_table_or_alert_text():
    _, document = finding()
    text = adf_text(document)
    assert '| --- |' not in text
    assert '[!CAUTION]' not in text
    assert '<details>' not in text
    assert 'CVSS vector' in text


def test_document_only_uses_nodes_that_jira_accepts_and_cve_text_cannot_mention():
    _, document = finding()
    allowed = {'doc', 'paragraph', 'text', 'panel', 'heading', 'table', 'tableRow', 'tableHeader', 'tableCell',
               'orderedList', 'bulletList', 'listItem', 'blockquote', 'hardBreak'}
    for node in walk(document):
        assert node['type'] in allowed
        if node['type'] == 'text':
            assert node['text']


def test_marker_and_fix_date_survive_for_later_scans():
    _, document = finding()
    text = adf_text(document)
    assert MARKER_PATTERN.findall(text) == ['openbao/CVE-2026-1234']
    assert read_fix_date(text) == date(2026, 11, 10)


def test_cve_text_cannot_fake_a_marker():
    text = adf_text(markdown_to_adf('&lt;!-- vuln-watch-id: x/CVE-1 -->\n\n&lt;**!-- vuln-watch-id: x/CVE-2 -->**'))
    assert MARKER_PATTERN.findall(text) == []


def test_escaped_text_reads_normally():
    assert inline('a &lt;b> c') == [{'type': 'text', 'text': 'a <b> c'}]


def test_only_web_links_become_links():
    assert inline('[x](javascript:alert)') == [{'type': 'text', 'text': '[x](javascript:alert)'}]
    assert inline('[x](https://a.test)')[0]['marks'][0]['attrs']['href'] == 'https://a.test'


def test_table_cells_keep_escaped_pipes_and_line_breaks():
    document = markdown_to_adf('| A | B |\n| --- | --- |\n| x\\|y | one<br>two |')
    header, row = document['content'][0]['content']
    assert header['content'][0]['type'] == 'tableHeader'
    first, second = row['content']
    assert first['content'][0]['content'][0]['text'] == 'x|y'
    assert [node['type'] for node in second['content'][0]['content']] == ['text', 'hardBreak', 'text']


def test_plain_quote_is_a_blockquote():
    assert types(markdown_to_adf('> quoted')) == ['blockquote']


def test_fix_date_reader():
    assert read_fix_date('> **Fix by:** 2026-11-05 (2 days)') == date(2026, 11, 5)
    assert read_fix_date('**Fix by:** No deadline for this severity\nFix by: 2000-01-01') is None
    assert read_fix_date('Fix by: 2026-13-45') is None
    assert read_fix_date('nothing') is None
