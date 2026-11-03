from pathlib import Path

import pytest

from infra_vuln_watch.configuration.inventory import load_inventory, load_item

GOOD = 'name: a\nrepo: o/a\nversion: "1.2.3"\nteam: sre\nowner: me\nvendor: o\nproduct: a\n'


def write(tmp_path, text):
    path = tmp_path / "item.yaml"
    path.write_text(text)
    return path


def test_good_file_defaults_keyword_and_display_name_to_name(tmp_path):
    item = load_item(write(tmp_path, GOOD))
    assert item["keyword"] == "a"
    assert item["display_name"] == "a"


def test_missing_field(tmp_path):
    with pytest.raises(ValueError, match="owner"):
        load_item(write(tmp_path, GOOD.replace("owner: me\n", "")))


def test_unquoted_version_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="quotes"):
        load_item(write(tmp_path, GOOD.replace('"1.2.3"', "2.10")))


def test_empty_directory(tmp_path):
    with pytest.raises(ValueError):
        load_inventory(tmp_path)


def test_real_inventory_is_valid():
    assert load_inventory(Path(__file__).parents[1] / "inventory")[0]["name"] == "openbao"


def test_name_with_spaces_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="spaces"):
        load_item(write(tmp_path, GOOD.replace("name: a", "name: my tool")))


def test_duplicate_names_are_rejected(tmp_path):
    (tmp_path / "one.yaml").write_text(GOOD)
    (tmp_path / "two.yaml").write_text(GOOD)
    with pytest.raises(ValueError, match="Two inventory files"):
        load_inventory(tmp_path)


def test_team_is_required(tmp_path):
    with pytest.raises(ValueError, match="team"):
        load_item(write(tmp_path, GOOD.replace("team: sre\n", "")))


@pytest.mark.parametrize('replacement', ['42', 'true', '[]', '" "'])
def test_non_string_or_blank_name_is_a_clean_error(tmp_path, replacement):
    with pytest.raises(ValueError, match='non-empty string'):
        load_item(write(tmp_path, GOOD.replace('name: a', f'name: {replacement}')))


def test_malformed_yaml_is_a_clean_error(tmp_path):
    with pytest.raises(ValueError, match='could not read inventory'):
        load_item(write(tmp_path, 'name: [unterminated'))


def test_tab_in_name_is_rejected(tmp_path):
    with pytest.raises(ValueError, match='spaces'):
        load_item(write(tmp_path, GOOD.replace('name: a', 'name: "a\\tb"')))


def test_unreadable_file_is_a_clean_error(tmp_path):
    with pytest.raises(ValueError, match='could not read inventory'):
        load_item(tmp_path / 'missing.yaml')


MULTI = '''name: openbao
repo: openbao/openbao
vendor: openbao
product: openbao
team: sre
owner: default-owner
config:
  fix_days:
    high: 5
  outputs:
    jira:
      project: SEC
deployments:
  - id: prod-eu
    environment: production
    version: "2.5.5"
    owner: prod-owner
    config:
      fix_days:
        high: 3
  - id: stage
    environment: staging
    version: "2.6.4"
'''


def test_expands_deployments_with_versions_ownership_and_partial_config(tmp_path):
    write(tmp_path, MULTI)
    prod, staging = load_inventory(tmp_path)
    assert prod['name'] == staging['name'] == 'openbao'
    assert (prod['deployment_id'], prod['environment'], prod['version']) == ('prod-eu', 'production', '2.5.5')
    assert (prod['owner'], staging['owner']) == ('prod-owner', 'default-owner')
    assert prod['team'] == staging['team'] == 'sre'
    assert prod['config']['fix_days']['high'] == 3
    assert staging['config']['fix_days']['high'] == 5
    assert prod['config']['outputs']['jira']['project'] == 'SEC'
    # Inventory layers must not inject built-in defaults that would erase global values.
    assert 'low' not in prod['config']['fix_days']
    prod['config']['outputs']['jira']['project'] = 'OTHER'
    assert staging['config']['outputs']['jira']['project'] == 'SEC'


def test_missing_tool_owner_can_be_supplied_per_deployment(tmp_path):
    text = MULTI.replace('owner: default-owner\n', '').replace('    version: "2.6.4"', '    version: "2.6.4"\n    owner: stage-owner')
    write(tmp_path, text)
    prod, stage = load_inventory(tmp_path)
    assert prod['owner'] == 'prod-owner'
    assert stage['owner'] == 'stage-owner'


@pytest.mark.parametrize('text, message', [
    (MULTI.replace('id: stage', 'id: prod-eu'), 'duplicate deployment id'),
    (MULTI.replace('id: stage', 'id: "stage bad"'), 'deployment id'),
    (MULTI.replace('environment: staging', 'environment: 12'), 'non-empty string'),
    (MULTI.replace('version: "2.6.4"', 'version: 2.10'), 'quotes'),
    (MULTI.replace('    version: "2.6.4"\n', ''), 'version'),
    (MULTI.replace('deployments:\n', 'version: "1.0"\ndeployments:\n'), 'inside each deployment'),
    (MULTI.replace('    environment: staging', '    typo: staging'), 'unknown deployment fields'),
    (MULTI[:MULTI.index('deployments:')] + 'deployments: []\n', 'non-empty list'),
    (MULTI[:MULTI.index('deployments:')] + 'deployments: null\n', 'non-empty list'),
    (MULTI[:MULTI.index('deployments:')] + 'deployments:\n  - invalid\n', 'mapping'),
])
def test_invalid_deployment_is_a_clean_validation_error(tmp_path, text, message):
    with pytest.raises(ValueError, match=message):
        load_item(write(tmp_path, text))


def test_environment_defaults_to_stable_deployment_id(tmp_path):
    write(tmp_path, MULTI.replace('    environment: production\n', ''))
    assert load_inventory(tmp_path)[0]['environment'] == 'prod-eu'


def test_grouped_metadata_preserves_targets_and_finding_ids(tmp_path):
    from textwrap import indent
    from infra_vuln_watch.domain.identity import inventory_id
    path = write(tmp_path, MULTI)
    legacy = load_inventory(tmp_path)
    metadata, remainder = MULTI.split('config:', 1)
    path.write_text('tool:\n' + indent(metadata, '  ') + 'config:' + remainder)
    grouped = load_inventory(tmp_path)
    assert grouped == legacy
    assert [inventory_id(item) for item in grouped] == ['openbao/prod-eu', 'openbao/stage']


def test_grouped_single_version_record(tmp_path):
    text = '''tool:
  name: a
  repo: o/a
  vendor: o
  product: a
  team: sre
  owner: me
version: "1.2.3"
'''
    item = load_item(write(tmp_path, text))
    assert item['name'] == 'a'
    assert item['version'] == '1.2.3'
    assert item['owner'] == 'me'


@pytest.mark.parametrize('text, message', [
    ('tool: null\n', 'tool must be a mapping'),
    ('tool: []\n', 'tool must be a mapping'),
    ('tool: {}\nname: a\n', 'do not mix'),
    ('tool:\n  typo: a\n', 'unknown tool fields'),
    ('tool: {}\nsettings: {}\n', 'unknown inventory sections'),
])
def test_invalid_grouped_sections_fail_cleanly(tmp_path, text, message):
    with pytest.raises(ValueError, match=message):
        load_item(write(tmp_path, text))


def test_yml_files_are_scanned_alongside_yaml(tmp_path):
    (tmp_path / 'a.yaml').write_text(GOOD)
    (tmp_path / 'b.yml').write_text(GOOD.replace('name: a', 'name: b'))
    assert [item['name'] for item in load_inventory(tmp_path)] == ['a', 'b']


def test_same_tool_in_yaml_and_yml_is_rejected(tmp_path):
    (tmp_path / 'a.yaml').write_text(GOOD)
    (tmp_path / 'a.yml').write_text(GOOD)
    with pytest.raises(ValueError, match='Two inventory files'):
        load_inventory(tmp_path)


def test_aliases_are_kept_for_every_target(tmp_path):
    (tmp_path / 'a.yaml').write_text(
        'tool:\n  name: a\n  repo: o/a\n  vendor: o\n  product: a\n  team: sre\n  owner: me\n'
        '  aliases:\n    - vendor: Other Name\n      product: A Server\n'
        'deployments:\n  - id: prod\n    version: "1.0"\n')
    (target,) = load_inventory(tmp_path)
    assert target['aliases'] == [{'vendor': 'Other Name', 'product': 'A Server'}]


@pytest.mark.parametrize('aliases', [
    'aliases: name\n',
    'aliases:\n  - name\n',
    'aliases:\n  - vendor: only\n',
    'aliases:\n  - vendor: v\n    product: p\n    extra: x\n',
    'aliases:\n  - vendor: ""\n    product: p\n',
])
def test_invalid_aliases_are_rejected(tmp_path, aliases):
    with pytest.raises(ValueError, match='alias'):
        load_item(write(tmp_path, GOOD + aliases))
