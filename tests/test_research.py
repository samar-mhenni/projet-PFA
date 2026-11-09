import json
from types import SimpleNamespace
import pytest
from redcrew.research import prepare_research, packet, TOPICS
from redcrew.diagnostics import safe_error


def test_research_covers_evidence_and_roles_before_model():
    class Knowledge:
        queries = []
        def search(self, query):
            self.queries.append(query)
            return [{'attack_id': f'T{len(self.queries)}', 'name': 'Technique', 'url': 'https://attack.mitre.org/', 'excerpt': 'a' * 2000}]
        def related(self, rows):
            return [{'attack_id': 'M1', 'name': 'Mitigation', 'url': 'https://attack.mitre.org/', 'excerpt': 'linked mitigation'}]
    knowledge = Knowledge()
    engagement = {'objective': 'Review', 'evidence': [{'id': 'E1', 'content': 'x' * 1800 + 'last evidence sentence'}]}
    result = prepare_research(knowledge, engagement)
    assert any('last evidence sentence' in q for q in knowledge.queries)
    assert set(result['agent_packets']) == set(TOPICS)
    assert len(result['queries']) == 11
    assert any(r['attack_id'] == 'M1' for r in result['sources'])
    assert all(len(json.dumps(p, ensure_ascii=True)) <= 3000 for p in result['agent_packets'].values())
    assert result['sources'][0]['excerpt'] == 'a' * 2000


def test_packet_deduplicates():
    row = {'attack_id': 'T1', 'name': 'test', 'url': 'source', 'excerpt': 'evidence'}
    assert len(packet([row, row])) == 1


def test_error_chain_preserved_without_credentials(monkeypatch):
    monkeypatch.setenv('LLM_API_KEY', 'private-credential')
    try:
        try:
            raise ValueError('provider rejected private-credential and gsk_abc123')
        except ValueError as cause:
            raise Exception('outer error') from cause
    except Exception as exc:
        result = safe_error(exc)
    assert 'outer error' in result and 'provider rejected' in result
    assert 'private-credential' not in result and 'gsk_abc123' not in result


def test_partial_outputs_survive_failure(tmp_path, monkeypatch):
    from redcrew import cli, crew, knowledge
    from test_reliability import ENGAGEMENT, SOURCES
    def build(k, **kwargs):
        def kickoff(**inputs):
            kwargs['task_callback'](SimpleNamespace(agent='Planning', raw='Completed planning'))
            raise Exception('Provider returned an empty completion')
        return SimpleNamespace(agents=[SimpleNamespace(llm=object())], kickoff=kickoff)
    monkeypatch.setattr(crew, 'build_crew', build)
    monkeypatch.setattr(knowledge, 'Knowledge', lambda path: SimpleNamespace(search=lambda q: SOURCES[0]['results'], retrievals=SOURCES, collection=SimpleNamespace(metadata={})))
    monkeypatch.setenv('LLM_API_KEY', 'test-key')
    path = tmp_path / 'engagement.json'
    path.write_text(json.dumps({**ENGAGEMENT, 'name': 'Test', 'authorized': True, 'objective': 'Review', 'evidence': [{**ENGAGEMENT['evidence'][0], 'kind': 'config'}]}))
    monkeypatch.setattr('sys.argv', ['redcrew', 'run', str(path), '--output', str(tmp_path / 'reports')])
    with pytest.raises(SystemExit):
        cli.main()
    folder = next((tmp_path / 'reports').iterdir())
    audit = json.loads((folder / 'audit.json').read_text())
    assert audit['tasks'][0]['agent'] == 'Planning'
    assert 'empty completion' in audit['error']
    assert (folder / 'research.json').exists()
    assert not (folder / 'report.md').exists()
