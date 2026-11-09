import json
import pytest
from redcrew.engagement import load_engagement
from redcrew.knowledge import records, Knowledge


def test_scope_and_authorization(tmp_path):
    data = json.loads(open('examples/engagement.json').read())
    path = tmp_path / 'engagement.json'
    path.write_text(json.dumps(data))
    assert load_engagement(path)['authorized']
    data['evidence'][0]['target'] = 'outside.test'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='outside'):
        load_engagement(path)
    data['authorized'] = False
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='authorized'):
        load_engagement(path)


def bundle():
    return {'type': 'bundle', 'objects': [
        {'id': 'attack-pattern--test', 'type': 'attack-pattern', 'name': 'Test technique', 'description': 'SSH remote access', 'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1021.004', 'url': 'https://attack.mitre.org/techniques/T1021/004/'}]},
        {'id': 'attack-pattern--revoked', 'type': 'attack-pattern', 'revoked': True}
    ]}


def test_records_exclude_revoked_and_preserve_citations():
    rows = list(records(bundle()))
    assert len(rows) == 1
    assert rows[0]['metadata']['attack_id'] == 'T1021.004'
    assert rows[0]['metadata']['url'].startswith('https://attack.mitre.org/')
    with pytest.raises(ValueError):
        list(records({}))


def test_duplicate_evidence(tmp_path):
    data = json.loads(open('examples/engagement.json').read())
    data['evidence'].append(data['evidence'][0])
    path = tmp_path / 'input.json'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='unique'):
        load_engagement(path)


def test_vector_ingest_search_and_reimport(tmp_path):
    path = tmp_path / 'stix.json'
    path.write_text(json.dumps(bundle()))
    knowledge = Knowledge(tmp_path / 'db')
    with pytest.raises(ValueError, match='empty'):
        knowledge.search('SSH')
    assert knowledge.ingest(path)['chunks'] == 1
    assert knowledge.ingest(path)['chunks'] == 1
    result = knowledge.search('SSH remote access')
    assert result[0]['attack_id'] == 'T1021.004'
    assert result[0]['excerpt']
    replacement = bundle()
    replacement['objects'][0]['external_references'][0]['external_id'] = 'T0000'
    path.write_text(json.dumps(replacement))
    knowledge.ingest(path)
    assert knowledge.search('SSH')[0]['attack_id'] == 'T0000'
    path.write_text('{"type":"bundle","objects":[]}')
    with pytest.raises(ValueError, match='no supported'):
        knowledge.ingest(path)
    assert knowledge.search('SSH')[0]['attack_id'] == 'T0000'


def test_relationships_require_matching_snapshot(tmp_path):
    data = bundle()
    data['objects'] += [
        {'id': 'course-of-action--test', 'type': 'course-of-action', 'name': 'Restrict access', 'description': 'Restrict SSH access to authorized accounts.', 'external_references': [{'source_name': 'mitre-attack', 'external_id': 'M0001', 'url': 'https://attack.mitre.org/mitigations/M0001/'}]},
        {'id': 'relationship--test', 'type': 'relationship', 'relationship_type': 'mitigates', 'source_ref': 'course-of-action--test', 'target_ref': 'attack-pattern--test'}
    ]
    path = tmp_path / 'stix.json'
    path.write_text(json.dumps(data))
    knowledge = Knowledge(tmp_path / 'db')
    knowledge.ingest(path)
    related = knowledge.related([{'attack_id': 'T1021.004'}])
    assert related[0]['attack_id'] == 'M0001'
    assert related[0]['relationship']['type'] == 'mitigates'
    path.write_text(json.dumps(bundle()))
    assert knowledge.related([{'attack_id': 'T1021.004'}]) == []
