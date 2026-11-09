"""Export reproducible scripts and explicitly unexecuted agent suggestions."""
import hashlib
import json
from pathlib import Path
import re


def export_scripts(folder, audit):
    folder = Path(folder)
    scripts = folder / 'scripts'
    scripts.mkdir(exist_ok=True)
    entries = []

    def save(name, content, status, description, agent=None):
        path = scripts / name
        path.write_text(content)
        entries.append({'file': name, 'status': status, 'description': description,
                        'agent': agent, 'sha256': hashlib.sha256(content.encode()).hexdigest()})

    engagement = audit['engagement']
    if len(engagement['targets']) == 1 and engagement['targets'][0].startswith(('http://', 'https://')):
        from . import target
        save('collector_snapshot.py', Path(target.__file__).read_text(),
             'collector_used_by_application' if audit.get('collection_method') == 'http_get' else 'current_collector_reference',
             'HTTP collector source snapshot. Historical runs do not establish which source revision was used.')
        script = ('"""Replay HTTP collection; this replay script was not executed during the assessment."""\n'
                  'import json\nfrom collector_snapshot import collect_target\n\n'
                  f'target = {engagement["targets"][0]!r}\n'
                  "print(json.dumps(collect_target(target), indent=2))\n")
        save('replay_http.py', script, 'replay_not_executed', 'Makes a new HTTP request and prints new evidence; responses may differ from the original.')
    queries = [r['query'] for r in audit.get('retrievals', []) if r.get('query') and not r['query'].startswith('STIX relationship expansion')]
    save('queries.json', json.dumps(queries, indent=2), 'recorded_searches', 'Queries recorded during the investigation; excludes relationship expansion.')
    save('replay_searches.py', '''"""Replay recorded vector searches with the installed RedCrew environment; no LLM calls."""
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from redcrew.knowledge import Knowledge
load_dotenv()
knowledge = Knowledge(os.getenv('VECTORDB_PATH', 'data/chroma'))
queries = json.loads(Path(__file__).with_name('queries.json').read_text())
print(json.dumps([{'query': q, 'results': knowledge.search(q)} for q in queries], indent=2))
''', 'replay_not_executed', 'Searches the current vector index; its snapshot may differ from the original run.')
    extensions = {'python': 'py', 'py': 'py', 'bash': 'sh', 'sh': 'sh', 'shell': 'sh', 'powershell': 'ps1', 'javascript': 'js'}
    for index, task in enumerate(audit.get('tasks', []), 1):
        for block, match in enumerate(re.finditer(r'^```([^\n]*)\n(.*?)^```\s*$', task.get('output', ''), re.MULTILINE | re.DOTALL), 1):
            language = match.group(1).strip().lower()
            if language not in extensions:
                continue
            save(f'agent_{index:02d}_proposal_{block:02d}.{extensions[language]}', match.group(2), 'proposed_not_executed',
                 'Untrusted agent-generated code. Review before manually running. Export does not execute it.', task.get('agent'))
    for record in audit.get('executions', []):
        entries.append({'file': 'executed/' + Path(record['script']).name, 'status': record['status'], 'agent': record['agent'], 'sha256': record['sha256'], 'exit_code': record.get('exit_code')})
    manifest = {'note': 'Agents can execute fixed HTTP checks only when execution records are present. Arbitrary shell execution is unavailable. Exported replay scripts and agent proposals were not executed. Only explicit collection metadata identifies application-used collector code.', 'artifacts': entries}
    (scripts / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    (scripts / 'README.md').write_text('# Investigation scripts\n\n' + manifest['note'] + '\n\nSee manifest.json for provenance and hashes. Agent scripts are exported only when an agent actually emitted a supported fenced code block; none are invented. Run replay scripts from the project root with its virtual environment activated.\n')
    return scripts
