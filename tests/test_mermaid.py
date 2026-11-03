"""Every Mermaid diagram in the repository must parse, as GitHub cannot draw one that does not.

The parser needs Node.js and `npm ci` in scripts/mermaid. Those tests skip without them on a local
machine, but fail in CI, so a missing setup cannot pass unnoticed.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / 'scripts' / 'mermaid'
SKIPPED_FOLDERS = {'.git', '.venv', 'node_modules', '.pytest_cache', 'build', 'dist'}
FENCE = re.compile(r'^```mermaid\n(.*?)^```', re.MULTILINE | re.DOTALL)


def find_diagrams():
    """Return (name, source) for every diagram in every Markdown file."""
    found = []
    for path in sorted(ROOT.rglob('*.md')):
        relative = path.relative_to(ROOT)
        if SKIPPED_FOLDERS & set(relative.parts):
            continue
        for number, source in enumerate(FENCE.findall(path.read_text(encoding='utf-8')), start=1):
            found.append((f'{relative.as_posix()}#{number}', source))
    return found


DIAGRAMS = find_diagrams()


def parse(diagrams):
    """Return the real Mermaid parser's error for each diagram, or None if it parsed."""
    if not shutil.which('node') or not (CHECKER / 'node_modules').is_dir():
        message = 'needs Node.js and `npm ci` in scripts/mermaid'
        if os.environ.get('CI'):
            pytest.fail(message)
        pytest.skip(message)
    result = subprocess.run(['node', 'check.mjs'], cwd=CHECKER, input=json.dumps(diagrams), text=True,
                            capture_output=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.fixture(scope='module')
def parse_errors():
    return dict(zip((name for name, _ in DIAGRAMS), parse([source for _, source in DIAGRAMS])))


def test_diagrams_are_found_in_every_documentation_area():
    names = [name for name, _ in DIAGRAMS]
    for expected in ('docs/arc42/06-runtime-view.md', 'docs/c4/', 'docs/adr/', 'docs/diataxis/', 'README.md', 'knowledge/'):
        assert any(name.startswith(expected) for name in names), expected


@pytest.mark.parametrize('name', [name for name, _ in DIAGRAMS])
def test_diagram_parses(parse_errors, name):
    assert parse_errors[name] is None, f'{name}: {parse_errors[name]}'


@pytest.mark.parametrize('name,source', [item for item in DIAGRAMS if item[1].lstrip().startswith('sequenceDiagram')],
                         ids=[item[0] for item in DIAGRAMS if item[1].lstrip().startswith('sequenceDiagram')])
def test_sequence_messages_have_no_semicolons(name, source):
    """Needs no Node.js. A semicolon ends a statement, so the rest of the message breaks the diagram."""
    assert [line.strip() for line in source.splitlines() if ';' in line] == []


def test_parser_rejects_a_semicolon_in_a_sequence_message():
    """Guards the check itself, using the mistake that once broke the runtime view on GitHub."""
    broken = 'sequenceDiagram\n    participant M as Scanner\n    M->>M: Expand deployments; merge global, tool and deployment settings\n'
    assert parse([broken])[0] is not None


def test_parser_accepts_a_colon_in_a_quoted_flowchart_label():
    assert parse(['flowchart LR\n    a["Maintainer: Person"] --> b["Scanner"]\n'])[0] is None
