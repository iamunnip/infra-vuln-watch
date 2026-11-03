"""Regression checks for documentation validation, using isolated bundles."""

from pathlib import Path
import runpy

import pytest

validator = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/check_docs.py'))
check = validator['check']


@pytest.fixture
def bundle(tmp_path):
    knowledge = tmp_path / 'knowledge'
    knowledge.mkdir()
    (knowledge / 'index.md').write_text('---\nokf_version: "0.2"\n---\n')
    (knowledge / 'log.md').write_text('# Updates\n')
    (knowledge / 'topic.md').write_text(
        '---\ntype: Concept\ntitle: Topic\ndescription: A domain fact.\n---\n# Topic\n'
    )
    (tmp_path / 'docs').mkdir()
    return tmp_path


def test_bundle_root_links_and_duplicate_heading_anchors(bundle):
    (bundle / 'knowledge/index.md').write_text(
        '---\nokf_version: "0.2"\n---\n[Topic](/topic.md#topic)\n'
    )
    (bundle / 'docs/page.md').write_text(
        '# A `CLI`\n# A CLI\n[First](#a-cli)\n[Second](#a-cli-1)\n'
        '[Reference][topic]\n\n[topic]: ../knowledge/topic.md#topic\n'
        '```md\n[Example](missing.md)\n# Example\n```\n'
        '`[Inline example](missing.md)`\n'
    )
    assert check(bundle) == []


def test_missing_file_anchor_and_reference_definition_are_reported(bundle):
    (bundle / 'docs/page.md').write_text(
        '[Missing](lost.md)\n[Heading](../knowledge/topic.md#lost)\n'
        '[Reference][missing]\n\n[missing]: absent.md\n'
    )
    errors = check(bundle)
    assert len(errors) == 3
    assert any('missing heading anchor' in error for error in errors)
    assert any('lost.md' in error for error in errors)
    assert any('absent.md' in error for error in errors)


@pytest.mark.parametrize('frontmatter', [
    '# Missing metadata\n',
    '---\ntype: Concept\n',
    '---\n- Concept\n---\n',
    '---\ntype: Concept\ntitle: Topic\ndescription: []\n---\n',
    '---\ntype: [\n---\n',
])
def test_invalid_concept_metadata_fails(bundle, frontmatter):
    (bundle / 'knowledge/topic.md').write_text(frontmatter)
    assert check(bundle)


def test_wrong_bundle_version_and_missing_log_fail(bundle):
    (bundle / 'knowledge/index.md').write_text('---\nokf_version: "0.1"\n---\n')
    (bundle / 'knowledge/log.md').unlink()
    errors = check(bundle)
    assert len(errors) == 2
    assert any('okf_version' in error for error in errors)
    assert any('log.md' in error for error in errors)


def test_external_links_are_skipped_but_repository_escape_fails(bundle):
    (bundle / 'docs/page.md').write_text(
        '[Remote](https://example.com/no-page#nothing)\n'
        '[Escape](../../outside.md)\n'
    )
    errors = check(bundle)
    assert len(errors) == 1
    assert 'escapes repository' in errors[0]
