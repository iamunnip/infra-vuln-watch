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


def test_bundle_links_and_duplicate_heading_anchors(bundle):
    (bundle / 'knowledge/index.md').write_text(
        '---\nokf_version: "0.2"\n---\n[Topic](topic.md#topic)\n'
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


def test_the_repository_itself_passes():
    assert check(Path(__file__).resolve().parents[1]) == []


def test_leading_slash_link_in_the_bundle_is_reported_because_github_cannot_find_it(bundle):
    (bundle / 'knowledge/index.md').write_text('---\nokf_version: "0.2"\n---\n[Topic](/topic.md)\n')
    errors = check(bundle)
    assert len(errors) == 1
    assert 'not found on GitHub' in errors[0]


def test_leading_slash_link_in_the_bundle_is_reported_even_if_the_repo_root_has_that_file(bundle):
    (bundle / 'topic.md').write_text('# Topic\n')
    (bundle / 'knowledge/index.md').write_text('---\nokf_version: "0.2"\n---\n[Topic](/topic.md)\n')
    assert any('not found on GitHub' in error for error in check(bundle))


def test_leading_slash_link_outside_the_bundle_resolves_from_the_repository_root(bundle):
    (bundle / 'docs/page.md').write_text('[Topic](/knowledge/topic.md)\n[Lost](/topic.md)\n')
    errors = check(bundle)
    assert len(errors) == 1
    assert '/topic.md' in errors[0]


def test_relative_links_between_bundle_folders_are_followed(bundle):
    (bundle / 'knowledge/area').mkdir()
    (bundle / 'knowledge/area/index.md').write_text('[Topic](../topic.md#topic)\n[Wrong](topic.md)\n')
    errors = check(bundle)
    assert len(errors) == 1
    assert 'missing link target: topic.md' in errors[0]


@pytest.mark.parametrize('name', ['README.md', 'scripts/mermaid/nested/README.md', 'other/guide.md'])
def test_markdown_files_anywhere_are_checked(bundle, name):
    (bundle / name).parent.mkdir(parents=True, exist_ok=True)
    (bundle / name).write_text('[Lost](lost.md)\n')
    assert any('lost.md' in error for error in check(bundle))


def test_generated_folders_are_not_checked(bundle):
    (bundle / 'node_modules/package').mkdir(parents=True)
    (bundle / 'node_modules/package/README.md').write_text('[Lost](lost.md)\n')
    assert check(bundle) == []


@pytest.mark.parametrize('name,text', [
    ('src/module.py', '# See docs/adr/0001-lost.md for why.\n'),
    ('config.yaml', '# See docs/diataxis/lost.md\n'),
    ('docs/page.md', 'Edit `inventory/lost.yaml` first.\n'),
    ('.github/workflows/run.yml', '# Uses scripts/lost.py\n'),
])
def test_files_named_in_plain_text_must_exist(bundle, name, text):
    (bundle / name).parent.mkdir(parents=True, exist_ok=True)
    (bundle / name).write_text(text)
    assert any('names a file that does not exist' in error for error in check(bundle))


def test_existing_and_example_files_and_history_can_be_named(bundle):
    (bundle / 'docs/adr').mkdir()
    (bundle / 'tests').mkdir()
    (bundle / 'docs/page.md').write_text('See `knowledge/topic.md` and create `inventory/vault.yaml`.\n')
    (bundle / 'docs/adr/0001-old.md').write_text('# Old\nThis moved from docs/old/place.md.\n')
    (bundle / 'tests/test_x.py').write_text("FIXTURE = 'docs/made-up.md'\n")
    assert check(bundle) == []


@pytest.mark.parametrize('url,target', [
    ('https://github.com/iamunnip/infra-vuln-watch/blob/main/vulnerability-data/index.md', 'vulnerability-data/index.md'),
    ('https://github.com/iamunnip/infra-vuln-watch/tree/main/lost', 'lost'),
    ('https://github.com/iamunnip/infra-vuln-watch/actions/workflows/lost.yml/badge.svg', '.github/workflows/lost.yml'),
])
def test_own_github_urls_must_point_at_existing_files(bundle, url, target):
    (bundle / 'docs/page.md').write_text(f'[Link]({url})\n')
    errors = check(bundle)
    assert len(errors) == 1
    assert target in errors[0]


def test_own_github_urls_to_existing_files_pass_and_other_repositories_are_skipped(bundle):
    (bundle / 'docs/page.md').write_text(
        '[Topic](https://github.com/iamunnip/infra-vuln-watch/blob/main/knowledge/topic.md#topic)\n'
        '[Other](https://github.com/openbao/openbao/blob/main/lost.md)\n'
    )
    assert check(bundle) == []

