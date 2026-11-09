import json
from redcrew.artifacts import export_scripts


def test_export_does_not_execute_agent_scripts(tmp_path):
    sentinel = tmp_path / 'must-not-exist'
    code = f'from pathlib import Path\nPath({str(sentinel)!r}).touch()\n'
    audit = {'engagement': {'targets': ['http://localhost:8080/']}, 'collection_method': 'http_get', 'tasks': [{'agent': '../../malicious', 'output': '```python\n' + code + '```\n'}], 'retrievals': [{'query': 'SSH', 'results': []}]}
    folder = export_scripts(tmp_path, audit)
    assert not sentinel.exists()
    assert (folder / 'agent_01_proposal_01.py').read_text() == code
    statuses = {x['file']: x['status'] for x in json.loads((folder / 'manifest.json').read_text())['artifacts']}
    assert statuses['agent_01_proposal_01.py'] == 'proposed_not_executed'
    assert statuses['collector_snapshot.py'] == 'collector_used_by_application'
    assert statuses['replay_http.py'] == 'replay_not_executed'
    for path in folder.glob('*.py'):
        compile(path.read_text(), str(path), 'exec')


def test_historical_export_does_not_claim_execution(tmp_path):
    folder = export_scripts(tmp_path, {'engagement': {'targets': ['http://localhost/']}, 'tasks': []})
    artifacts = json.loads((folder / 'manifest.json').read_text())['artifacts']
    assert next(x for x in artifacts if x['file'] == 'collector_snapshot.py')['status'] == 'current_collector_reference'
    assert not list(folder.glob('agent_*'))
