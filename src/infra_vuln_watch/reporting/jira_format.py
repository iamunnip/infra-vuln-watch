"""Turn the Markdown of a finding into Atlassian Document Format for Jira.

Only the Markdown that issue_format writes is understood. Everything else stays plain text, and
no mention, media or other active node is ever built, so CVE text cannot notify anyone.
"""

import re
from typing import Any

from infra_vuln_watch.domain.identity import MARKER_PATTERN

INLINE = re.compile(r'`(?P<code>[^`]+)`|\*\*(?P<strong>.+?)\*\*|\[(?P<label>[^\]]+)\]\((?P<href>[^)\s]+)\)|(?P<br><br>)')
ALERT = re.compile(r'\[!(?P<kind>[A-Z]+)\]')
PANEL_TYPES = {'CAUTION': 'error', 'WARNING': 'warning', 'NOTE': 'note', 'IMPORTANT': 'info', 'TIP': 'success'}
TABLE_SEPARATOR = re.compile(r'\|(\s*-+\s*\|)+')
TABLE_CELL = re.compile(r'(?<!\\)\|')
NUMBERED = re.compile(r'\d+\. ')
# Escaped "<" reads better restored, but restoring "<!--" could fake a finding marker.
ESCAPED_LESS_THAN = re.compile(r'&lt;(?!!--)')


def text_node(text, *marks):
    node: dict[str, Any] = {'type': 'text', 'text': ESCAPED_LESS_THAN.sub('<', text)}
    if marks:
        node['marks'] = list(marks)
    return node


def inline(text):
    """Return text, strong, code and link nodes for one line. ADF rejects empty text nodes."""
    nodes = []
    position = 0
    for match in INLINE.finditer(text):
        if match.start() > position:
            nodes.append(text_node(text[position:match.start()]))
        position = match.end()
        if match['code']:
            nodes.append(text_node(match['code'], {'type': 'code'}))
        elif match['strong']:
            nodes.append(text_node(match['strong'], {'type': 'strong'}))
        elif match['br']:
            nodes.append({'type': 'hardBreak'})
        elif match['href'].startswith(('https://', 'http://')):
            nodes.append(text_node(match['label'], {'type': 'link', 'attrs': {'href': match['href']}}))
        else:
            nodes.append(text_node(match[0]))
    if position < len(text):
        nodes.append(text_node(text[position:]))
    return nodes


def paragraph(text):
    return {'type': 'paragraph', 'content': inline(text)}


def table_row(line, cell_type):
    cells = TABLE_CELL.split(line.strip())[1:-1]
    return {'type': 'tableRow', 'content': [
        {'type': cell_type, 'content': [paragraph(cell.strip().replace('\\|', '|'))]} for cell in cells
    ]}


def is_table_start(lines, index):
    return (lines[index].startswith('|') and index + 1 < len(lines)
            and bool(TABLE_SEPARATOR.fullmatch(lines[index + 1].strip())))


def quote_block(lines):
    """Return a panel for a GitHub alert, or a block quote for any other quoted lines."""
    texts = [line.removeprefix('>').strip() for line in lines]
    alert = ALERT.fullmatch(texts[0])
    content = [paragraph(text) for text in texts[1 if alert else 0:] if text]
    content = content or [{'type': 'paragraph', 'content': []}]
    if alert:
        return {'type': 'panel', 'attrs': {'panelType': PANEL_TYPES.get(alert['kind'], 'info')}, 'content': content}
    return {'type': 'blockquote', 'content': content}


def list_block(lines, index, list_type, prefix):
    """Return (list node, next line index) for consecutive items that prefix recognises."""
    items = []
    while index < len(lines) and (match := prefix.match(lines[index])):
        items.append({'type': 'listItem', 'content': [paragraph(lines[index][match.end():])]})
        index += 1
    return {'type': list_type, 'content': items}, index


BULLET = re.compile(r'- ')


def markdown_to_adf(body):
    """Return the ADF document for a finding body, keeping its marker as exact plain text."""
    lines = body.splitlines()
    content: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped or stripped in {'<details>', '</details>'}:
            index += 1
        elif MARKER_PATTERN.fullmatch(stripped):
            content.append({'type': 'paragraph', 'content': [{'type': 'text', 'text': stripped}]})
            index += 1
        elif stripped.startswith('<summary>') and stripped.endswith('</summary>'):
            content.append({'type': 'heading', 'attrs': {'level': 3},
                            'content': inline(stripped[len('<summary>'):-len('</summary>')])})
            index += 1
        elif line.startswith('### ') or line.startswith('## '):
            level, _, title = line.partition(' ')
            content.append({'type': 'heading', 'attrs': {'level': len(level)}, 'content': inline(title.strip())})
            index += 1
        elif line.startswith('>'):
            end = index
            while end < len(lines) and lines[end].startswith('>'):
                end += 1
            content.append(quote_block(lines[index:end]))
            index = end
        elif is_table_start(lines, index):
            rows = [table_row(line, 'tableHeader')]
            index += 2
            while index < len(lines) and lines[index].startswith('|'):
                rows.append(table_row(lines[index], 'tableCell'))
                index += 1
            content.append({'type': 'table', 'content': rows})
        elif NUMBERED.match(line):
            node, index = list_block(lines, index, 'orderedList', NUMBERED)
            content.append(node)
        elif BULLET.match(line):
            node, index = list_block(lines, index, 'bulletList', BULLET)
            content.append(node)
        else:
            content.append(paragraph(stripped))
            index += 1
    return {'type': 'doc', 'version': 1, 'content': content}
